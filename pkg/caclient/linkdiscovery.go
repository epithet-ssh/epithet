package caclient

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// relAuth is the extension relation type the CA uses to advertise its auth
// config document. RFC 8288 requires extension relation types to be URIs. It
// carries no version segment: the relation names the relationship, not the
// payload schema.
const relAuth = "https://epithet.dev/rel/auth"

// findLinkTarget returns the target of the first link-value in h whose rel
// list contains rel. A single rel parameter may hold several space-separated
// relation types (RFC 8288 3.3), so membership is tested, not equality.
func findLinkTarget(h http.Header, rel string) (string, bool) {
	for _, field := range h.Values("Link") {
		for _, lv := range splitLinkValues(field) {
			target, params, ok := parseLinkValue(lv)
			if !ok {
				continue
			}
			for _, candidate := range strings.Fields(params["rel"]) {
				if candidate == rel {
					return target, true
				}
			}
		}
	}
	return "", false
}

// splitLinkValues splits one Link field value into its comma-separated
// link-values, ignoring commas inside angle brackets or quoted strings.
func splitLinkValues(s string) []string {
	var out []string
	var buf strings.Builder
	var inAngle, inQuote, escaped bool

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			buf.WriteByte(ch)
			escaped = false
			continue
		}
		switch {
		case inQuote && ch == '\\':
			escaped = true
		case ch == '"':
			inQuote = !inQuote
		case ch == '<' && !inQuote:
			inAngle = true
		case ch == '>' && !inQuote:
			inAngle = false
		case ch == ',' && !inQuote && !inAngle:
			out = append(out, buf.String())
			buf.Reset()
			continue
		}
		buf.WriteByte(ch)
	}
	if strings.TrimSpace(buf.String()) != "" {
		out = append(out, buf.String())
	}
	return out
}

// parseLinkValue splits one link-value into its target and parameters.
// Parameter values are accepted in both token and quoted-string form, which
// RFC 8288 3 requires recipients to treat as equivalent. Only the first
// occurrence of a parameter is kept, per RFC 8288 3.3. Parameters are split on
// semicolons without quote awareness: the only parameter read is rel, whose
// values never contain one.
func parseLinkValue(lv string) (string, map[string]string, bool) {
	lv = strings.TrimSpace(lv)
	if !strings.HasPrefix(lv, "<") {
		return "", nil, false
	}
	end := strings.Index(lv, ">")
	if end < 0 {
		return "", nil, false
	}

	target := lv[1:end]
	params := map[string]string{}

	for _, p := range strings.Split(lv[end+1:], ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key, value, found := strings.Cut(p, "=")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		}
		if _, dup := params[key]; !dup {
			params[key] = value
		}
	}
	return target, params, true
}

// resolveLinkTarget resolves a Link target reference against the URL a
// response actually came from.
//
// The base is that URL's scheme, host, and path only, with a trailing slash
// forced: ca-url names a collection, and RFC 3986 5 would otherwise drop its
// last segment ("/epithet/ca" + "discovery" resolves to "/epithet/discovery").
// Query and fragment are dropped because neither is meaningful for a
// collection base. This normalization is internal — the configured ca-url is
// never rewritten.
func resolveLinkTarget(final *url.URL, ref string) (*url.URL, error) {
	parsed, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("invalid Link target %q: %w", ref, err)
	}

	base := &url.URL{Scheme: final.Scheme, Host: final.Host, Path: final.Path}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}

	return base.ResolveReference(parsed), nil
}

// sameOrigin reports whether a and b share scheme, host, and port. A Link
// target is a URI-Reference, so an absolute cross-host value is legal; we
// reject it to keep TLS trust anchored to the configured host.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}
