package scim

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"

	elimity "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/optional"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
)

// These handlers translate Elimity's validated attributes into our user and
// group models. Protocol resources stop here; storage implements complete directory operations.
type userHandler struct {
	store           directory.Store
	userIDAttribute string
}
type groupHandler struct{ store directory.Store }

var _ elimity.ResourceHandler = userHandler{}
var _ elimity.ResourceHandler = groupHandler{}

func (h userHandler) Create(r *http.Request, a elimity.ResourceAttributes) (elimity.Resource, error) {
	u, err := provisionedUser(a)
	if err != nil {
		return elimity.Resource{}, err
	}
	// Epithet assigns the resource identity before storage using configuration,
	// never the client's read-only SCIM id (which Elimity ignores).
	if strings.HasPrefix(h.userIDAttribute, strings.ToLower(enterpriseSchema)+":") {
		extension, _ := a[enterpriseSchema].(map[string]any)
		u.ID = attributeText(extension, strings.TrimPrefix(h.userIDAttribute, strings.ToLower(enterpriseSchema)+":"))
	} else {
		u.ID = attributeText(a, h.userIDAttribute)
	}
	if strings.TrimSpace(u.ID) == "" {
		return elimity.Resource{}, scimerrors.ScimError{Status: 400, Detail: h.userIDAttribute + " is required to assign the user ID"}
	}
	if strings.Contains(u.ID, "bulkId") {
		return elimity.Resource{}, scimerrors.ScimError{Status: 400, Detail: "user ID must not contain the reserved SCIM keyword bulkId"}
	}
	if err := u.Validate(); err != nil {
		return elimity.Resource{}, storageError(err)
	}
	event := directory.NewAuditEvent(r.Context(), "create", u.ID)
	u.Created = event.Time
	u.Modified = u.Created
	u, err = h.store.CreateUser(r.Context(), u, event)
	return userResult(u, err)
}
func (h userHandler) Replace(r *http.Request, id string, a elimity.ResourceAttributes) (elimity.Resource, error) {
	u, err := provisionedUser(a)
	if err != nil {
		return elimity.Resource{}, err
	}
	u.ID = id // The URL owns SCIM resource identity.
	if err := u.Validate(); err != nil {
		return elimity.Resource{}, storageError(err)
	}
	expected, err := h.expectedVersion(r, id)
	if err != nil {
		return elimity.Resource{}, storageError(err)
	}
	event := directory.NewAuditEvent(r.Context(), "replace", u.ID)
	u.Modified = event.Time
	u, err = h.store.ReplaceUser(r.Context(), u, expected, event)
	return userResult(u, err)
}
func (h userHandler) Get(r *http.Request, id string) (elimity.Resource, error) {
	u, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		return elimity.Resource{}, storageError(err)
	}
	if u == nil {
		return elimity.Resource{}, storageError(directory.ErrNotFound)
	}
	return userResource(*u), nil
}
func (h userHandler) GetAll(r *http.Request, p elimity.ListRequestParams) (elimity.Page, error) {
	if p.FilterValidator != nil {
		return elimity.Page{}, scimerrors.ScimErrorInvalidFilter
	}
	users, total, err := h.store.ListUsers(r.Context(), p.StartIndex, p.Count)
	if err != nil {
		return elimity.Page{}, storageError(err)
	}
	resources := make([]elimity.Resource, 0, len(users))
	for _, u := range users {
		resources = append(resources, userResource(u))
	}
	return elimity.Page{Resources: resources, TotalResults: total}, nil
}
func (h userHandler) Delete(r *http.Request, id string) error {
	expected, err := h.expectedVersion(r, id)
	if err != nil {
		return storageError(err)
	}
	event := directory.NewAuditEvent(r.Context(), "delete", id)
	return storageError(h.store.DeleteUser(r.Context(), id, expected, event.Time, event))
}

// expectedVersion selects a version matching the currently returned resource.
// The backend determines whether the write enforces that version atomically.
func (h userHandler) expectedVersion(r *http.Request, id string) (string, error) {
	match := strings.TrimSpace(r.Header.Get("If-Match"))
	if match == "" || match == "*" {
		return "", nil
	}
	current, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		return "", err
	}
	if current == nil {
		return "", directory.ErrNotFound
	}
	return matchingVersion(match, current.Version)
}

func (h userHandler) Patch(*http.Request, string, []elimity.PatchOperation) (elimity.Resource, error) {
	return elimity.Resource{}, scimerrors.ScimError{Status: http.StatusNotImplemented}
}

func (h groupHandler) Create(r *http.Request, a elimity.ResourceAttributes) (elimity.Resource, error) {
	g, err := provisionedGroup(a)
	if err != nil {
		return elimity.Resource{}, err
	}
	g.ID = rand.Text() // SCIM resource IDs are assigned by Epithet, not the client.
	if err := g.Validate(); err != nil {
		return elimity.Resource{}, storageError(err)
	}
	event := directory.NewAuditEvent(r.Context(), "create", g.ID)
	g.Created = event.Time
	g.Modified = g.Created
	g, err = h.store.CreateGroup(r.Context(), g, event)
	return groupResult(g, err)
}
func (h groupHandler) Replace(r *http.Request, id string, a elimity.ResourceAttributes) (elimity.Resource, error) {
	g, err := provisionedGroup(a)
	if err != nil {
		return elimity.Resource{}, err
	}
	g.ID = id // The URL owns SCIM resource identity.
	if err := g.Validate(); err != nil {
		return elimity.Resource{}, storageError(err)
	}
	expected, err := h.expectedVersion(r, id)
	if err != nil {
		return elimity.Resource{}, storageError(err)
	}
	event := directory.NewAuditEvent(r.Context(), "replace", g.ID)
	g.Modified = event.Time
	g, err = h.store.ReplaceGroup(r.Context(), g, expected, event)
	return groupResult(g, err)
}
func (h groupHandler) Get(r *http.Request, id string) (elimity.Resource, error) {
	g, err := h.store.GetGroup(r.Context(), id)
	if err != nil {
		return elimity.Resource{}, storageError(err)
	}
	if g == nil {
		return elimity.Resource{}, storageError(directory.ErrNotFound)
	}
	return groupResource(*g), nil
}
func (h groupHandler) GetAll(r *http.Request, p elimity.ListRequestParams) (elimity.Page, error) {
	if p.FilterValidator != nil {
		return elimity.Page{}, scimerrors.ScimErrorInvalidFilter
	}
	groups, total, err := h.store.ListGroups(r.Context(), p.StartIndex, p.Count)
	if err != nil {
		return elimity.Page{}, storageError(err)
	}
	resources := make([]elimity.Resource, 0, len(groups))
	for _, g := range groups {
		resources = append(resources, groupResource(g))
	}
	return elimity.Page{Resources: resources, TotalResults: total}, nil
}
func (h groupHandler) Delete(r *http.Request, id string) error {
	expected, err := h.expectedVersion(r, id)
	if err != nil {
		return storageError(err)
	}
	event := directory.NewAuditEvent(r.Context(), "delete", id)
	return storageError(h.store.DeleteGroup(r.Context(), id, expected, event))
}

// expectedVersion selects a version matching the currently returned resource.
// The backend determines whether the write enforces that version atomically.
func (h groupHandler) expectedVersion(r *http.Request, id string) (string, error) {
	match := strings.TrimSpace(r.Header.Get("If-Match"))
	if match == "" || match == "*" {
		return "", nil
	}
	current, err := h.store.GetGroup(r.Context(), id)
	if err != nil {
		return "", err
	}
	if current == nil {
		return "", directory.ErrNotFound
	}
	return matchingVersion(match, current.Version)
}

func (h groupHandler) Patch(*http.Request, string, []elimity.PatchOperation) (elimity.Resource, error) {
	return elimity.Resource{}, scimerrors.ScimError{Status: http.StatusNotImplemented}
}

func attributeText(a map[string]any, key string) string {
	for name, value := range a {
		if strings.EqualFold(name, key) {
			s, _ := value.(string)
			return s
		}
	}
	return ""
}

func provisionedUser(a elimity.ResourceAttributes) (directory.ManagedUser, error) {
	u := directory.ManagedUser{ExternalID: attributeText(a, "externalId"), UserName: attributeText(a, "userName"), Active: true, UserType: attributeText(a, "userType")}
	if _, exists := a["password"]; exists {
		return u, scimerrors.ScimError{Status: 400, Detail: "password provisioning is not supported"}
	}
	if active, ok := a["active"].(bool); ok {
		u.Active = active
	}
	if enterprise, ok := a[enterpriseSchema].(map[string]any); ok {
		u.Department, u.Organization = attributeText(enterprise, "department"), attributeText(enterprise, "organization")
	}
	return u, nil
}

func provisionedGroup(a elimity.ResourceAttributes) (directory.ManagedGroup, error) {
	g := directory.ManagedGroup{ExternalID: attributeText(a, "externalId"), DisplayName: attributeText(a, "displayName"), MemberIDs: []string{}}
	members, _ := a["members"].([]any)
	seen := make(map[string]bool, len(members))
	for _, raw := range members {
		member := raw.(map[string]any) // Validated by the Group schema.
		if typ := attributeText(member, "type"); typ != "" && typ != "User" {
			return g, scimerrors.ScimError{Status: 400, Detail: "only direct User memberships are supported"}
		}
		id := attributeText(member, "value")
		if !seen[id] {
			g.MemberIDs = append(g.MemberIDs, id)
			seen[id] = true
		}
	}
	return g, nil
}

func userResult(u directory.ManagedUser, err error) (elimity.Resource, error) {
	if err != nil {
		return elimity.Resource{}, storageError(err)
	}
	return userResource(u), nil
}
func groupResult(g directory.ManagedGroup, err error) (elimity.Resource, error) {
	if err != nil {
		return elimity.Resource{}, storageError(err)
	}
	return groupResource(g), nil
}
func userResource(u directory.ManagedUser) elimity.Resource {
	a := elimity.ResourceAttributes{"userName": u.UserName, "active": u.Active}
	if u.UserType != "" {
		a["userType"] = u.UserType
	}
	enterprise := map[string]any{}
	if u.Department != "" {
		enterprise["department"] = u.Department
	}
	if u.Organization != "" {
		enterprise["organization"] = u.Organization
	}
	if len(enterprise) > 0 {
		a[enterpriseSchema] = enterprise
	}
	return wireResource(u.Metadata, u.ExternalID, a)
}
func groupResource(g directory.ManagedGroup) elimity.Resource {
	members := make([]map[string]any, 0, len(g.MemberIDs))
	for _, id := range g.MemberIDs {
		members = append(members, map[string]any{"value": id, "type": "User"})
	}
	return wireResource(g.Metadata, g.ExternalID, elimity.ResourceAttributes{"displayName": g.DisplayName, "members": members})
}
func wireResource(m directory.Metadata, externalID string, a elimity.ResourceAttributes) elimity.Resource {
	return elimity.Resource{ID: m.ID, ExternalID: optional.NewString(externalID), Attributes: a,
		Meta: elimity.Meta{Created: &m.Created, LastModified: &m.Modified, Version: versionETag(m.Version)}}
}

// Escape opaque backend tokens into HTTP-safe entity tags. Numeric SQLite
// versions retain their existing representation; only the adapter knows ETags.
func versionETag(version string) string {
	if version == "" {
		return ""
	}
	return `W/"` + url.PathEscape(version) + `"`
}

func matchingVersion(match, version string) (string, error) {
	for _, tag := range strings.Split(match, ",") {
		if strings.TrimSpace(tag) == versionETag(version) {
			return version, nil
		}
	}
	return "", directory.ErrVersion
}

func storageError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, directory.ErrNotFound):
		return scimerrors.ScimError{Status: 404, Detail: err.Error()}
	case errors.Is(err, directory.ErrConflict):
		return scimerrors.ScimErrorUniqueness
	case errors.Is(err, directory.ErrVersion):
		return scimerrors.ScimError{Status: 412, Detail: err.Error()}
	case errors.Is(err, directory.ErrInvalid):
		return scimerrors.ScimError{Status: 400, Detail: err.Error()}
	default:
		return scimerrors.ScimError{Status: 503, Detail: "directory unavailable"}
	}
}
