package scim

import (
	"errors"
	"net/http"
	"strings"

	elimity "github.com/elimity-com/scim"
	scimerrors "github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/optional"
	"github.com/epithet-ssh/epithet/pkg/directory"
)

// These handlers translate Elimity's validated attributes into our user and
// group models. Protocol resources stop here; storage owns atomic mutations.
type userHandler struct{ store directory.Store }
type groupHandler struct{ store directory.Store }

var _ elimity.ResourceHandler = userHandler{}
var _ elimity.ResourceHandler = groupHandler{}

func (h userHandler) Create(r *http.Request, a elimity.ResourceAttributes) (elimity.Resource, error) {
	u, err := provisionedUser(a)
	if err != nil {
		return elimity.Resource{}, err
	}
	u, err = h.store.CreateUser(r.Context(), u)
	return userResult(u, err)
}
func (h userHandler) Replace(r *http.Request, id string, a elimity.ResourceAttributes) (elimity.Resource, error) {
	u, err := provisionedUser(a)
	if err != nil {
		return elimity.Resource{}, err
	}
	u, err = h.store.ReplaceUser(r.Context(), id, u, r.Header.Get("If-Match"))
	return userResult(u, err)
}
func (h userHandler) Get(r *http.Request, id string) (elimity.Resource, error) {
	u, err := h.store.GetUser(r.Context(), id)
	return userResult(u, err)
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
	return storageError(h.store.DeleteUser(r.Context(), id, r.Header.Get("If-Match")))
}
func (h userHandler) Patch(*http.Request, string, []elimity.PatchOperation) (elimity.Resource, error) {
	return elimity.Resource{}, scimerrors.ScimError{Status: http.StatusMethodNotAllowed}
}

func (h groupHandler) Create(r *http.Request, a elimity.ResourceAttributes) (elimity.Resource, error) {
	g, err := provisionedGroup(a)
	if err != nil {
		return elimity.Resource{}, err
	}
	g, err = h.store.CreateGroup(r.Context(), g)
	return groupResult(g, err)
}
func (h groupHandler) Replace(r *http.Request, id string, a elimity.ResourceAttributes) (elimity.Resource, error) {
	g, err := provisionedGroup(a)
	if err != nil {
		return elimity.Resource{}, err
	}
	g, err = h.store.ReplaceGroup(r.Context(), id, g, r.Header.Get("If-Match"))
	return groupResult(g, err)
}
func (h groupHandler) Get(r *http.Request, id string) (elimity.Resource, error) {
	g, err := h.store.GetGroup(r.Context(), id)
	return groupResult(g, err)
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
	return storageError(h.store.DeleteGroup(r.Context(), id, r.Header.Get("If-Match")))
}
func (h groupHandler) Patch(*http.Request, string, []elimity.PatchOperation) (elimity.Resource, error) {
	return elimity.Resource{}, scimerrors.ScimError{Status: http.StatusMethodNotAllowed}
}

func attributeText(a map[string]any, key string) string {
	s, _ := a[key].(string)
	return s
}

func provisionedUser(a elimity.ResourceAttributes) (directory.ManagedUser, error) {
	u := directory.ManagedUser{ExternalID: attributeText(a, "externalId"), UserName: attributeText(a, "userName"), Active: true, UserType: attributeText(a, "userType")}
	if strings.TrimSpace(u.ExternalID) == "" {
		return u, scimerrors.ScimError{Status: 400, Detail: "externalId is required"}
	}
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

func provisionedGroup(a elimity.ResourceAttributes) (directory.Group, error) {
	g := directory.Group{ExternalID: attributeText(a, "externalId"), DisplayName: attributeText(a, "displayName"), MemberIDs: []string{}}
	members, _ := a["members"].([]any)
	for _, raw := range members {
		member := raw.(map[string]any) // Validated by the Group schema.
		if typ := attributeText(member, "type"); typ != "" && typ != "User" {
			return g, scimerrors.ScimError{Status: 400, Detail: "only direct User memberships are supported"}
		}
		g.MemberIDs = append(g.MemberIDs, attributeText(member, "value"))
	}
	return g, nil
}

func userResult(u directory.ManagedUser, err error) (elimity.Resource, error) {
	if err != nil {
		return elimity.Resource{}, storageError(err)
	}
	return userResource(u), nil
}
func groupResult(g directory.Group, err error) (elimity.Resource, error) {
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
func groupResource(g directory.Group) elimity.Resource {
	members := make([]map[string]any, 0, len(g.MemberIDs))
	for _, id := range g.MemberIDs {
		members = append(members, map[string]any{"value": id, "type": "User"})
	}
	return wireResource(g.Metadata, g.ExternalID, elimity.ResourceAttributes{"displayName": g.DisplayName, "members": members})
}
func wireResource(m directory.Metadata, externalID string, a elimity.ResourceAttributes) elimity.Resource {
	return elimity.Resource{ID: m.ID, ExternalID: optional.NewString(externalID), Attributes: a,
		Meta: elimity.Meta{Created: &m.Created, LastModified: &m.Modified, Version: m.ETag()}}
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
