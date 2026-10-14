// Package scim adapts SCIM provisioning to the directory storage contract.
// Elimity handles SCIM routing, schemas, validation, and response formatting;
// Epithet owns authentication, identity rules, and directory operations.
package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	elimity "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/optional"
	"github.com/elimity-com/scim/schema"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
)

const enterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

const maxBody = 4 << 20
const maxPage = 1000

type Handler struct {
	server      http.Handler
	patchUsers  bool
	patchGroups bool
	versioning  bool
}

// NewBackend serves the existing SCIM API behind authenticated control requests.
// The caller must verify control's signed request before dispatching here.
// userIDAttribute selects a stored string attribute used to assign user IDs on
// creation. Empty defaults to externalId. Later updates retain the resource ID.
func NewBackend(store directory.Store, userIDAttribute string) (*Handler, error) {
	if store == nil {
		return nil, fmt.Errorf("SCIM requires a store")
	}
	if userIDAttribute == "" {
		userIDAttribute = "externalId"
	}
	userIDAttribute = strings.ToLower(userIDAttribute)
	switch userIDAttribute {
	case "externalid", "username", "usertype",
		strings.ToLower(enterpriseSchema) + ":department",
		strings.ToLower(enterpriseSchema) + ":organization":
	default:
		return nil, fmt.Errorf("unsupported SCIM user ID attribute %q: select a stored string attribute", userIDAttribute)
	}
	patchUsers, patchGroups := store.SupportsPatchUser(), store.SupportsPatchGroup()
	server, err := elimity.NewServer(&elimity.ServerArgs{
		ServiceProviderConfig: &elimity.ServiceProviderConfig{
			MaxResults: maxPage,
			// SCIM exposes one service-wide flag, not a flag per resource type.
			SupportPatch: patchUsers || patchGroups,
		},
		ResourceTypes: []elimity.ResourceType{
			{ID: optional.NewString("User"), Name: "User", Endpoint: "/Users", Schema: selectedAttributes(schema.CoreUserSchema(), "userName", "active", "userType", "password"),
				SchemaExtensions: []elimity.SchemaExtension{{Schema: selectedAttributes(schema.ExtensionEnterpriseUser(), "department", "organization")}}, Handler: userHandler{store: store, userIDAttribute: userIDAttribute}},
			{ID: optional.NewString("Group"), Name: "Group", Endpoint: "/Groups", Schema: groupSchema(), Handler: groupHandler{store}},
		},
	}, elimity.WithBaseURL("/scim/v2"))
	if err != nil {
		return nil, err
	}
	return &Handler{server: server, patchUsers: patchUsers, patchGroups: patchGroups, versioning: store.SupportsVersioning()}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	defer r.Body.Close()

	path, ok := strings.CutPrefix(r.URL.Path, "/scim/v2/")
	if !ok {
		writeError(w, http.StatusNotFound, "unknown SCIM endpoint")
		return
	}
	if r.Method == http.MethodPatch {
		resource, _, _ := strings.Cut(path, "/")
		if (resource == "Users" && !h.patchUsers) || (resource == "Groups" && !h.patchGroups) {
			writeError(w, http.StatusNotImplemented, "PATCH is not supported for "+resource)
			return
		}
	}
	// The adapter implements the same limited provisioning operations as Store.
	// Do not silently ignore requests for unsupported filtering or sorting.
	for key := range r.URL.Query() {
		if key != "startIndex" && key != "count" {
			writeError(w, http.StatusBadRequest, "unsupported query parameter: "+key)
			return
		}
	}
	// Elimity hardcodes etag.supported=false. Serve capability discovery here
	// so it describes the configured store, including optional versioning.
	if r.Method == http.MethodGet && strings.TrimSuffix(path, "/") == "ServiceProviderConfig" {
		h.serviceProviderConfig(w)
		return
	}
	r = r.Clone(r.Context())
	r.URL.Path = "/v2/" + strings.TrimSuffix(path, "/")
	r.URL.RawPath = ""
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	h.server.ServeHTTP(w, r)
}

// serviceProviderConfig owns discovery for the capabilities exposed by this adapter.
func (h *Handler) serviceProviderConfig(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]bool{"supported": h.patchUsers || h.patchGroups},
		"bulk":           map[string]any{"supported": false, "maxOperations": 1000, "maxPayloadSize": 1048576},
		"filter":         map[string]any{"supported": false, "maxResults": maxPage},
		"changePassword": map[string]bool{"supported": false},
		"sort":           map[string]bool{"supported": false},
		"etag":           map[string]bool{"supported": h.versioning},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Control bearer token",
			"description": "Optional provisioning token or OIDC identity with directory-admin access", "primary": true,
		}},
	})
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
