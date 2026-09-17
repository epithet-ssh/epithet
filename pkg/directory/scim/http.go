// Package scim adapts SCIM provisioning to the directory storage contract.
// Elimity handles SCIM routing, schemas, validation, and response formatting;
// Epithet owns authentication, identity rules, and atomic directory mutations.
package scim

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	elimity "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/optional"
	"github.com/elimity-com/scim/schema"
	"github.com/epithet-ssh/epithet/pkg/directory"
)

const enterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

const maxBody = 4 << 20
const maxPage = 1000

type Handler struct {
	server    http.Handler
	tokenHash [32]byte
}

// New serves /scim/v2 with a distinct operator-supplied provisioning credential.
// Library types stay within this adapter; storage remains behind Store.
func New(store directory.Store, token string) (*Handler, error) {
	if store == nil || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, fmt.Errorf("SCIM requires a store and nonempty bearer token without whitespace")
	}
	server, err := elimity.NewServer(&elimity.ServerArgs{
		ServiceProviderConfig: &elimity.ServiceProviderConfig{
			MaxResults: maxPage,
			AuthenticationSchemes: []elimity.AuthenticationScheme{{
				Type: elimity.AuthenticationTypeOauthBearerToken, Name: "Provisioning bearer token",
				Description: "Operator-supplied provisioning token", Primary: true,
			}},
		},
		ResourceTypes: []elimity.ResourceType{
			{ID: optional.NewString("User"), Name: "User", Endpoint: "/Users", Schema: selectedAttributes(schema.CoreUserSchema(), "userName", "active", "userType", "password"),
				SchemaExtensions: []elimity.SchemaExtension{{Schema: selectedAttributes(schema.ExtensionEnterpriseUser(), "department", "organization")}}, Handler: userHandler{store}},
			{ID: optional.NewString("Group"), Name: "Group", Endpoint: "/Groups", Schema: groupSchema(), Handler: groupHandler{store}},
		},
	}, elimity.WithBaseURL("/scim/v2"))
	if err != nil {
		return nil, err
	}
	return &Handler{server: server, tokenHash: sha256.Sum256([]byte(token))}, nil
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
		writeError(w, http.StatusUnauthorized, "invalid provisioning credential")
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/scim/v2/")
	if !ok {
		writeError(w, http.StatusNotFound, "unknown SCIM endpoint")
		return
	}
	if r.Method == http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "PATCH is not supported")
		return
	}
	// The adapter implements the same limited provisioning operations as Store.
	// Do not silently ignore requests for unsupported filtering or sorting.
	for key := range r.URL.Query() {
		if key != "startIndex" && key != "count" {
			writeError(w, http.StatusBadRequest, "unsupported query parameter: "+key)
			return
		}
	}
	r = r.Clone(r.Context())
	r.URL.Path = "/v2/" + strings.TrimSuffix(path, "/")
	r.URL.RawPath = ""
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	h.server.ServeHTTP(w, r)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scimerrors.ScimError{Status: status, Detail: detail})
}

// Select the supported subset of Elimity's standard definitions so validation
// and discovery agree. Password remains recognized solely to reject provisioning.
func selectedAttributes(s schema.Schema, names ...string) schema.Schema {
	attributes := make(schema.Attributes, 0, len(names))
	for _, name := range names {
		attribute, ok := s.Attributes.ContainsAttribute(name)
		if !ok {
			panic("missing SCIM schema attribute: " + name)
		}
		attributes = append(attributes, attribute)
	}
	s.Attributes = attributes
	return s
}

func groupSchema() schema.Schema {
	s := selectedAttributes(schema.CoreGroupSchema(), "displayName")
	s.Attributes = append(s.Attributes, schema.ComplexCoreAttribute(schema.ComplexParams{
		Name: "members", MultiValued: true,
		SubAttributes: []schema.SimpleParams{
			schema.SimpleStringParams(schema.StringParams{Name: "value", Required: true, CaseExact: true}),
			schema.SimpleStringParams(schema.StringParams{Name: "type", CanonicalValues: []string{"User"}}),
		},
	}))
	return s
}
