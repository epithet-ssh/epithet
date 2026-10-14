package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

func (s *Server) scim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")
	fields := strings.Fields(r.Header.Get("Authorization"))
	token := ""
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
		token = fields[1]
	}
	actor := "scim"
	if !matchesSecret(token, s.config.SCIMToken) {
		auth, rejected := s.authorizeAdmin(r.Context(), token, s.config.DirectoryAdmins, "directory-admin")
		if rejected != nil {
			if rejected.Status == 401 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			}
			scimError(w, rejected.Status, rejected.Message)
			return
		}
		actor = auth.Actor
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
	if err != nil || len(body) > 4<<20 {
		scimError(w, 413, "request too large")
		return
	}
	result, err := s.provision(r.Context(), servicehttp.Request{Actor: actor, Method: r.Method, URL: r.URL.RequestURI(), ContentType: r.Header.Get("Content-Type"), IfMatch: r.Header.Get("If-Match"), Body: body})
	if err != nil {
		var rejected *facts.ServiceError
		if errors.As(err, &rejected) {
			scimError(w, rejected.Status, rejected.Message)
		} else {
			scimError(w, 503, "SCIM backend unavailable")
		}
		return
	}
	// Preserve the provisioning protocol's status and metadata without exposing
	// the private service transport or forwarding its authentication headers.
	for _, name := range []string{"Content-Type", "ETag", "Location", "WWW-Authenticate"} {
		value := result.Header.Get(name)
		if value != "" {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(result.Status)
	w.Write(result.Body)
}

func scimError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": fmt.Sprint(status), "detail": detail})
}

// scimBase discovers on every operation, so provider configuration changes take
// effect immediately. Only initial OPTIONS 4xx or an absent relation mean
// data-only service; transport errors, redirects and 5xx remain failures.
func (s *Server) scimBase(ctx context.Context) (*url.URL, error) {
	resp, err := s.directory.Do(ctx, servicehttp.Request{Method: "OPTIONS", URL: s.directory.Endpoint()}, 65536)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", facts.ErrUnavailable, err)
	}
	if resp.Status >= 400 && resp.Status < 500 {
		return nil, nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return nil, fmt.Errorf("%w: SCIM discovery HTTP %d", facts.ErrUnavailable, resp.Status)
	}
	raw, ok := wire.FindLinkTarget(resp.Header, wire.RelSCIM)
	if !ok {
		return nil, nil
	}
	target, err := s.directory.Resolve(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid SCIM base URL: %w", facts.ErrUnavailable, err)
	}
	if target.RawQuery != "" || target.ForceQuery {
		return nil, fmt.Errorf("%w: invalid SCIM base URL", facts.ErrUnavailable)
	}
	target.Path = strings.TrimRight(target.Path, "/") + "/"
	if target.RawPath != "" {
		target.RawPath = strings.TrimRight(target.RawPath, "/") + "/"
	}
	return target, nil
}

// provision preserves the method, escaped resource path, raw query, body and
// conditional write header. request.URL is the public SCIM request URI.
// The signed subject is the authenticated actor;
// shared-secret provisioning uses the nonhuman actor "scim".
func (s *Server) provision(ctx context.Context, request servicehttp.Request) (*servicehttp.Response, error) {
	target, err := url.ParseRequestURI(request.URL)
	if err != nil || target.IsAbs() || target.Host != "" || !strings.HasPrefix(target.EscapedPath(), "/scim/v2/") {
		return nil, &facts.ServiceError{Status: 400, Message: "invalid SCIM target"}
	}
	// Never let a public resource path escape the advertised SCIM base.
	for _, part := range strings.Split(target.Path, "/") {
		if part == "." || part == ".." || strings.Contains(part, "\\") {
			return nil, &facts.ServiceError{Status: 400, Message: "invalid SCIM resource path"}
		}
	}
	base, err := s.scimBase(ctx)
	if err != nil {
		return nil, err
	}
	if base == nil {
		return nil, &facts.ServiceError{Status: 404, Message: "provider does not support SCIM management"}
	}
	providerTarget := base.String() + strings.TrimPrefix(target.EscapedPath(), "/scim/v2/")
	if target.RawQuery != "" || target.ForceQuery {
		providerTarget += "?" + target.RawQuery
	}
	request.URL = providerTarget
	resp, err := s.directory.Do(ctx, request, 8<<20)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", facts.ErrUnavailable, err)
	}
	if resp.Status >= 300 && resp.Status < 400 {
		return nil, fmt.Errorf("%w: SCIM provider redirected request", facts.ErrUnavailable)
	}
	providerURL, _ := url.Parse(providerTarget)
	rebase := func(raw string) string { return scimPublicURL(raw, base, providerURL) }
	resp.Body = scimPublicBody(resp.Body, rebase)
	resp.Header.Set("Location", rebase(resp.Header.Get("Location")))
	return resp, nil
}

// scimPublicURL rebases only references into this provider's advertised SCIM
// tree. External references and unrelated URLs remain owned by the provider.
// Public references are origin-relative, as in the built-in SCIM adapter.
func scimPublicURL(raw string, base, request *url.URL) string {
	if raw == "" {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	resolved := request.ResolveReference(ref)
	if !strings.EqualFold(resolved.Scheme, base.Scheme) || !strings.EqualFold(resolved.Host, base.Host) {
		return raw
	}
	suffix, ok := strings.CutPrefix(resolved.EscapedPath(), base.EscapedPath())
	if !ok {
		return raw
	}
	result := "/scim/v2/" + suffix
	if resolved.RawQuery != "" || resolved.ForceQuery {
		result += "?" + resolved.RawQuery
	}
	if resolved.Fragment != "" {
		result += "#" + resolved.EscapedFragment()
	}
	return result
}

// scimPublicBody knows only standard SCIM URL-bearing fields: resource metadata,
// User groups and Group members, including resources in a ListResponse. Raw JSON
// keeps extension attributes (including large numbers) intact. It deliberately
// does not walk arbitrary extension objects or rewrite strings by prefix.
func scimPublicBody(body []byte, rebase func(string) string) []byte {
	var resource map[string]json.RawMessage
	if json.Unmarshal(body, &resource) != nil || resource == nil {
		return body
	}
	changed := false
	rewriteField := func(obj map[string]json.RawMessage, key string) bool {
		var old string
		if json.Unmarshal(obj[key], &old) != nil {
			return false
		}
		value := rebase(old)
		if value == old {
			return false
		}
		obj[key], _ = json.Marshal(value)
		return true
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(resource["meta"], &meta) == nil && rewriteField(meta, "location") {
		resource["meta"], _ = json.Marshal(meta)
		changed = true
	}
	var schemas []string
	_ = json.Unmarshal(resource["schemas"], &schemas)
	for _, schema := range schemas {
		field := ""
		switch schema {
		case "urn:ietf:params:scim:schemas:core:2.0:User":
			field = "groups"
		case "urn:ietf:params:scim:schemas:core:2.0:Group":
			field = "members"
		case "urn:ietf:params:scim:api:messages:2.0:ListResponse":
			var resources []json.RawMessage
			if json.Unmarshal(resource["Resources"], &resources) != nil {
				continue
			}
			listChanged := false
			for i, entry := range resources {
				updated := scimPublicBody(entry, rebase)
				if string(updated) != string(entry) {
					resources[i] = updated
					listChanged = true
				}
			}
			if listChanged {
				resource["Resources"], _ = json.Marshal(resources)
				changed = true
			}
		}
		if field == "" {
			continue
		}
		var refs []map[string]json.RawMessage
		if json.Unmarshal(resource[field], &refs) != nil {
			continue
		}
		refsChanged := false
		for _, ref := range refs {
			if rewriteField(ref, "$ref") {
				refsChanged = true
			}
		}
		if refsChanged {
			resource[field], _ = json.Marshal(refs)
			changed = true
		}
	}
	if !changed {
		return body
	}
	result, _ := json.Marshal(resource)
	return result
}
