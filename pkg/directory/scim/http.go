// Package scim owns SCIM provisioning documents, the storage contract, and HTTP
// handling. Authorization consumers depend only on the parent directory package.
package scim

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const maxBody = 4 << 20
const maxPage = 1000

type Handler struct {
	store     Store
	tokenHash [32]byte
}

// New mounts at /scim/v2 on either the standalone inventory listener or the
// combined router. The secret is a distinct operator-supplied provisioning
// credential; no OIDC or CA credentials are accepted by this boundary.
func New(store Store, token string) (*Handler, error) {
	if store == nil || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, fmt.Errorf("SCIM requires a store and nonempty bearer token without whitespace")
	}
	return &Handler{store: store, tokenHash: sha256.Sum256([]byte(token))}, nil
}
func fail(w http.ResponseWriter, status int, typ, detail string) {
	w.WriteHeader(status)
	body := map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": strconv.Itoa(status), "detail": detail}
	if typ != "" {
		body["scimType"] = typ
	}
	_ = json.NewEncoder(w).Encode(body)
}
func write(w http.ResponseWriter, status int, body any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	defer r.Body.Close()
	auth := strings.Fields(r.Header.Get("Authorization"))
	var token string
	if len(auth) == 2 && strings.EqualFold(auth[0], "Bearer") {
		token = auth[1]
	}
	hash := sha256.Sum256([]byte(token))
	if token == "" || subtle.ConstantTimeCompare(hash[:], h.tokenHash[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		fail(w, 401, "", "invalid provisioning credential")
		return
	}
	if strings.Contains(strings.ToLower(r.URL.RawPath), "%2f") {
		fail(w, 400, "invalidPath", "encoded path separators are not supported")
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/scim/v2/")
	if !ok {
		fail(w, 404, "", "unknown SCIM endpoint")
		return
	}
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && r.Method == http.MethodGet {
		switch parts[0] {
		case "ServiceProviderConfig":
			write(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, "patch": map[string]any{"supported": false}, "bulk": map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0}, "filter": map[string]any{"supported": false, "maxResults": maxPage}, "changePassword": map[string]any{"supported": false}, "sort": map[string]any{"supported": false}, "etag": map[string]any{"supported": true}, "authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "Provisioning bearer token", "description": "Operator-supplied provisioning token", "specUri": "https://www.rfc-editor.org/rfc/rfc6750", "primary": true}}})
			return
		case "ResourceTypes":
			write(w, 200, listResponse(resourceTypes(), 1, len(resourceTypes())))
			return
		case "Schemas":
			write(w, 200, listResponse(schemas(), 1, len(schemas())))
			return
		}
	}
	if len(parts) == 2 && r.Method == http.MethodGet && (parts[0] == "Schemas" || parts[0] == "ResourceTypes") {
		entries := schemas()
		if parts[0] == "ResourceTypes" {
			entries = resourceTypes()
		}
		for _, v := range entries {
			if v["id"] == parts[1] {
				write(w, 200, v)
				return
			}
		}
		fail(w, 404, "", "unknown schema or resource type")
		return
	}
	kind := Kind(parts[0])
	if kind != Users && kind != Groups || len(parts) > 2 {
		fail(w, 404, "", "unknown SCIM endpoint")
		return
	}
	id := ""
	if len(parts) == 2 {
		id = parts[1]
		if id == "" {
			fail(w, 404, "", "missing resource ID")
			return
		}
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(w, 400, "invalidValue", "invalid query")
		return
	}
	for key, values := range query {
		if len(values) != 1 {
			fail(w, 400, "invalidValue", "duplicate query parameter")
			return
		}
		if key != "startIndex" && key != "count" {
			typ := "invalidValue"
			if key == "filter" {
				typ = "invalidFilter"
			}
			fail(w, 400, typ, "unsupported query parameter: "+key)
			return
		}
		if r.Method != http.MethodGet || id != "" {
			fail(w, 400, "invalidValue", "pagination applies only to resource lists")
			return
		}
	}
	if id == "" {
		w.Header().Set("Allow", "GET, POST")
	} else {
		w.Header().Set("Allow", "GET, PUT, DELETE")
	}
	var resource Resource
	switch r.Method {
	case http.MethodGet:
		if id != "" {
			resource, err = h.store.Get(r.Context(), kind, id)
			break
		}
		start, count := 1, maxPage
		if v, ok := query["startIndex"]; ok {
			start, err = strconv.Atoi(v[0])
			if start < 1 {
				start = 1
			}
		}
		if err == nil {
			if v, ok := query["count"]; ok {
				count, err = strconv.Atoi(v[0])
				count = max(0, min(maxPage, count))
			}
		}
		if err != nil {
			fail(w, 400, "invalidValue", "pagination requires integer values")
			return
		}
		page, e := h.store.List(r.Context(), kind, start, count)
		if e != nil {
			h.storageError(w, e)
			return
		}
		resources := make([]map[string]any, 0, len(page.Resources))
		for _, v := range page.Resources {
			resources = append(resources, representation(v))
		}
		write(w, 200, listResponse(resources, start, page.Total))
		return
	case http.MethodPost, http.MethodPut:
		if r.Method == http.MethodPost && id != "" || r.Method == http.MethodPut && id == "" {
			fail(w, 405, "", "method not allowed at this endpoint")
			return
		}
		media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || media != "application/scim+json" && media != "application/json" {
			fail(w, 415, "", "SCIM JSON content type required")
			return
		}
		data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if e != nil {
			fail(w, 413, "", "resource exceeds size limit")
			return
		}
		doc, e := decodeDocument(kind, data)
		if e != nil {
			fail(w, 400, "invalidValue", e.Error())
			return
		}
		if r.Method == http.MethodPost {
			resource, err = h.store.Create(r.Context(), kind, doc)
		} else {
			resource, err = h.store.Replace(r.Context(), kind, id, doc, r.Header.Get("If-Match"))
		}
	case http.MethodDelete:
		if id == "" {
			fail(w, 405, "", "resource ID required")
			return
		}
		err = h.store.Delete(r.Context(), kind, id, r.Header.Get("If-Match"))
		if err == nil {
			w.WriteHeader(204)
			return
		}
	default:
		fail(w, 405, "", "operation not supported")
		return
	}
	if err != nil {
		h.storageError(w, err)
		return
	}
	w.Header().Set("ETag", resource.ETag())
	w.Header().Set("Location", resourceLocation(resource))
	status := 200
	if r.Method == http.MethodPost {
		status = 201
	}
	write(w, status, representation(resource))
}
func (h *Handler) storageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		fail(w, 404, "", err.Error())
	case errors.Is(err, ErrConflict):
		fail(w, 409, "uniqueness", err.Error())
	case errors.Is(err, ErrVersion):
		fail(w, 412, "", err.Error())
	case errors.Is(err, ErrInvalid):
		fail(w, 400, "invalidValue", err.Error())
	default:
		fail(w, 503, "", "directory unavailable")
	}
}
func resourceLocation(r Resource) string { return "/scim/v2/" + string(r.Kind) + "/" + r.ID }
func representation(r Resource) map[string]any {
	out := map[string]any{}
	for k, v := range r.Document {
		out[k] = v
	}
	out["id"] = r.ID
	out["meta"] = map[string]any{"resourceType": strings.TrimSuffix(string(r.Kind), "s"), "created": r.Created, "lastModified": r.Modified, "version": r.ETag(), "location": resourceLocation(r)}
	return out
}
func listResponse(resources []map[string]any, start, total int) map[string]any {
	return map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "Resources": resources, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources)}
}
func resourceTypes() []map[string]any {
	return []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": userSchema, "schemaExtensions": []any{map[string]any{"schema": enterpriseSchema, "required": false}}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": groupSchema},
	}
}
func schemas() []map[string]any {
	attribute := func(name, typ string, required, multi bool) map[string]any {
		return map[string]any{"name": name, "type": typ, "required": required, "multiValued": multi, "mutability": "readWrite", "returned": "default", "uniqueness": "none", "caseExact": true}
	}
	external := attribute("externalId", "string", true, false)
	external["uniqueness"] = "server"
	username := attribute("userName", "string", true, false)
	username["caseExact"] = false
	username["uniqueness"] = "server"
	members := attribute("members", "complex", false, true)
	members["subAttributes"] = []any{attribute("value", "string", true, false), attribute("display", "string", false, false), attribute("type", "string", false, false), attribute("$ref", "reference", false, false)}
	name := attribute("name", "complex", false, false)
	name["subAttributes"] = []any{attribute("formatted", "string", false, false), attribute("givenName", "string", false, false), attribute("familyName", "string", false, false), attribute("middleName", "string", false, false), attribute("honorificPrefix", "string", false, false), attribute("honorificSuffix", "string", false, false)}
	emails := attribute("emails", "complex", false, true)
	emails["subAttributes"] = []any{attribute("value", "string", false, false), attribute("type", "string", false, false), attribute("display", "string", false, false), attribute("primary", "boolean", false, false)}
	return []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": userSchema, "name": "User", "attributes": []any{external, username, name, emails, attribute("active", "boolean", false, false), attribute("displayName", "string", false, false), attribute("userType", "string", false, false)}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": groupSchema, "name": "Group", "attributes": []any{attribute("externalId", "string", false, false), attribute("displayName", "string", true, false), members}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}, "id": enterpriseSchema, "name": "EnterpriseUser", "attributes": []any{attribute("department", "string", false, false), attribute("organization", "string", false, false)}},
	}
}
