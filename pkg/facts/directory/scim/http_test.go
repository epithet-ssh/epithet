package scim_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/control"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/scim"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/test/controltest"
	"github.com/stretchr/testify/require"
)

// Fixed protocol identifiers keep these black-box tests independent of the adapter.
const (
	userSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

// document is only a test helper for examining HTTP response JSON.
type document map[string]json.RawMessage

func (d document) Text(key string) string {
	var value string
	_ = json.Unmarshal(d[key], &value)
	return value
}

func (d document) Version() string {
	var meta document
	_ = json.Unmarshal(d["meta"], &meta)
	return meta.Text("version")
}

type fixture struct {
	t       *testing.T
	store   *sqlitestore.Store
	handler http.Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s, e := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, e)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	f := controltest.New(t, s, s, nil, control.Config{SCIMToken: "provisioning-secret"})
	return &fixture{t, s, f.Control}
}
func (f *fixture) request(method, path, body, match string, status int) document {
	f.t.Helper()
	r := httptest.NewRequest(method, "/scim/v2/"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer provisioning-secret")
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("If-Match", match)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	require.Equal(f.t, status, w.Code, w.Body.String())
	require.Equal(f.t, "application/scim+json", w.Header().Get("Content-Type"))
	var d document
	if w.Body.Len() > 0 {
		require.NoError(f.t, json.Unmarshal(w.Body.Bytes(), &d))
	}
	if d.Version() != "" {
		require.Equal(f.t, d.Version(), w.Header().Get("ETag"))
	}
	return d
}
func user(external, name string, active bool) string {
	return fmt.Sprintf(`{"schemas":[%q],"externalId":%q,"userName":%q,"active":%t}`, userSchema, external, name, active)
}
func group(name string, ids ...string) string {
	members := []map[string]string{}
	for _, id := range ids {
		members = append(members, map[string]string{"value": id, "type": "User"})
	}
	b, _ := json.Marshal(map[string]any{"schemas": []string{groupSchema}, "displayName": name, "members": members})
	return string(b)
}
func (f *fixture) facts(id string) *directory.User {
	f.t.Helper()
	u, e := f.store.LookupUser(f.t.Context(), id)
	require.NoError(f.t, e)
	return u
}

func TestMissingReadsAndStorageFailures(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"Users/missing", "Groups/missing"} {
		f.request("GET", path, "", "", http.StatusNotFound)
	}
	// An unavailable store must not be mistaken for an absent resource.
	require.NoError(t, f.store.Close())
	for _, path := range []string{"Users/missing", "Groups/missing"} {
		f.request("GET", path, "", "", http.StatusInternalServerError)
	}
}

type patchCapabilitiesStore struct {
	directory.Store
	users, groups bool
}

func (s patchCapabilitiesStore) SupportsVersioning() bool { return false }

func (s patchCapabilitiesStore) SupportsPatchUser() bool  { return s.users }
func (s patchCapabilitiesStore) SupportsPatchGroup() bool { return s.groups }

func TestPatchCapabilityDiscoveryAndRejection(t *testing.T) {
	for _, tc := range []struct {
		name          string
		users, groups bool
	}{
		{name: "neither"},
		{name: "users", users: true},
		{name: "groups", groups: true},
		{name: "both", users: true, groups: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := scim.NewBackend(patchCapabilitiesStore{users: tc.users, groups: tc.groups}, "")
			require.NoError(t, err)
			f := &fixture{t: t, handler: handler}
			config := f.request("GET", "ServiceProviderConfig", "", "", 200)
			require.JSONEq(t, fmt.Sprintf(`{"supported":%t}`, tc.users || tc.groups), string(config["patch"]))
			for resource, supported := range map[string]bool{"Users": tc.users, "Groups": tc.groups} {
				// Supported resources reach the library's request validation;
				// unsupported resources are rejected without reading or mutating storage.
				status := http.StatusNotImplemented
				if supported {
					status = http.StatusBadRequest
				}
				response := f.request("PATCH", resource+"/subject", `{}`, "", status)
				require.Equal(t, fmt.Sprint(status), response.Text("status"))
				require.JSONEq(t, `["urn:ietf:params:scim:api:messages:2.0:Error"]`, string(response["schemas"]))
			}
		})
	}
}

func TestProvisioningLifecycleAndCurrentGroups(t *testing.T) {
	f := newFixture(t)
	a := f.request("POST", "Users", user("sub-alice", "alice", true), "", 201).Text("id")
	b := f.request("POST", "Users", user("sub-bob", "bob", true), "", 201).Text("id")
	require.Equal(t, "sub-alice", a)
	require.NotNil(t, f.facts(a))
	require.Nil(t, f.facts("alice"))
	g := f.request("POST", "Groups", group("ops", a), "", 201).Text("id")
	duplicate := f.request("POST", "Groups", group("ops", b), "", 201).Text("id")
	require.Equal(t, []directory.Group{{ID: g, Names: []string{"ops"}}}, f.facts("sub-alice").Groups)
	require.Equal(t, []directory.Group{{ID: duplicate, Names: []string{"ops"}}}, f.facts("sub-bob").Groups)
	groups, total, e := f.store.ListGroups(t.Context(), 1, 10)
	require.NoError(t, e)
	require.Len(t, groups, 2)
	require.Equal(t, 2, total)
	f.request("PUT", "Groups/"+g, group("renamed", a), "", 200)
	require.Equal(t, []directory.Group{{ID: g, Names: []string{"renamed"}}}, f.facts("sub-alice").Groups)
	f.request("PUT", "Users/"+a, user("sub-new", "renamed-alice", false), "", 200)
	require.Nil(t, f.facts("sub-new"))
	require.False(t, f.facts("sub-alice").Active)
	require.Equal(t, g, f.facts("sub-alice").Groups[0].ID)
	f.request("PUT", "Users/"+a, user("sub-new", "renamed-alice", true), "", 200)
	f.request("DELETE", "Groups/"+g, "", "", 204)
	f.request("GET", "Groups/"+g, "", "", 404)
	require.Empty(t, f.facts("sub-alice").Groups)
	replacement := f.request("POST", "Groups", group("ops", a), "", 201).Text("id")
	require.NotEqual(t, g, replacement)
	require.Equal(t, []directory.Group{{ID: replacement, Names: []string{"ops"}}}, f.facts("sub-alice").Groups)
	require.Equal(t, duplicate, f.facts("sub-bob").Groups[0].ID)
	events, _, e := f.store.Audit(t.Context(), "", 0)
	require.NoError(t, e)
	for _, event := range events {
		require.Contains(t, []string{"create", "replace", "delete"}, event.Action)
	}
	before, e := f.store.GetGroup(t.Context(), replacement)
	require.NoError(t, e)
	deleteStarted := time.Now().UTC()
	f.request("DELETE", "Users/"+a, "", "", 204)
	deleteFinished := time.Now().UTC()
	f.request("GET", "Users/"+a, "", "", 404)
	require.Nil(t, f.facts("sub-alice"))
	after, e := f.store.GetGroup(t.Context(), replacement)
	require.NoError(t, e)
	require.Empty(t, after.MemberIDs)
	require.NotEqual(t, after.Version, before.Version)
	require.True(t, before.Created.Equal(after.Created))
	require.False(t, after.Modified.Before(deleteStarted))
	require.False(t, after.Modified.After(deleteFinished))
	newID := f.request("POST", "Users", user("sub-new", "renamed-alice", true), "", 201).Text("id")
	require.NotEqual(t, a, newID)
	require.Empty(t, f.facts("sub-new").Groups)
}

func TestProtocolValidationPreconditionsAndPagination(t *testing.T) {
	f := newFixture(t)
	a := f.request("POST", "Users", user("alice-sub", "Alice", true), "", 201).Text("id")
	for _, body := range []string{user("other", "ALICE", true), user("alice-sub", "different", true)} {
		f.request("POST", "Users", body, "", 409)
	}
	for _, body := range []string{
		user("", "x", true), `{"schemas":[],"externalId":"x","userName":"x"}`,
		`null`, `[]`,
		strings.Replace(user("x", "x", true), `"active":true`, `"password":"secret"`, 1),
	} {
		f.request("POST", "Users", body, "", 400)
	}
	old := f.request("GET", "Users/"+a, "", "", 200).Version()
	f.request("PUT", "Users/"+a, user("alice-sub", "Renamed", true), old, 200)
	f.request("PUT", "Users/"+a, user("alice-sub", "stale", true), old, 412)
	f.request("DELETE", "Users/"+a, "", old, 412)
	require.Equal(t, "Renamed", f.facts("alice-sub").UserName)
	groups, total, e := f.store.ListGroups(t.Context(), 1, 10)
	require.NoError(t, e)
	f.request("POST", "Groups", group("bad", a, "missing"), "", 400)
	next, nextTotal, e := f.store.ListGroups(t.Context(), 1, 10)
	require.NoError(t, e)
	require.Equal(t, groups, next)
	require.Equal(t, total, nextTotal)
	f.request("POST", "Users", user("bob-sub", "Bob", true), "", 201)
	for _, tc := range []struct {
		query                  string
		total, items, pageSize int
	}{{"?count=0", 2, 0, 0}, {"?startIndex=2&count=1", 2, 1, 1}, {"?startIndex=3", 2, 0, 1000}, {"?startIndex=0&count=100000", 2, 2, 1000}} {
		d := f.request("GET", "Users"+tc.query, "", "", 200)
		require.Equal(t, fmt.Sprint(tc.total), string(d["totalResults"]))
		var resources []json.RawMessage
		require.NoError(t, json.Unmarshal(d["Resources"], &resources))
		require.Len(t, resources, tc.items)
		// Elimity reports the requested page size here, even on a partial page.
		require.Equal(t, fmt.Sprint(tc.pageSize), string(d["itemsPerPage"]))
	}
	for _, q := range []string{"?filter=userName%20eq%20%22Alice%22", "?count=oops"} {
		f.request("GET", "Users"+q, "", "", 400)
	}
	f.request("PATCH", "Users/"+a, `{}`, "", 501)
	config := f.request("GET", "ServiceProviderConfig", "", "", 200)
	require.JSONEq(t, `{"supported":false}`, string(config["patch"]))
	require.JSONEq(t, `{"supported":true}`, string(config["etag"]))
	f.request("GET", "Schemas/"+userSchema, "", "", 200)
	for _, token := range []string{"", "other", "oidc-token"} {
		r := httptest.NewRequest("GET", "/scim/v2/Users", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		require.Equal(t, 401, w.Code)
	}
}

func TestProvisioningKeepsRegisteredAttributes(t *testing.T) {
	f := newFixture(t)
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:example:extension"],"externalId":"subject","USERNAME":"alice","id":"forged","meta":{"version":"forged"},"groups":[{"value":"forged"}],"urn:example:extension":{"huge":9007199254740993,"nested":[true,null,"x"],"UserName":"opaque-case"}}`
	d := f.request("POST", "Users", body, "", 201)
	require.NotEqual(t, "forged", d.Text("id"))
	require.Equal(t, "alice", d.Text("userName"))
	require.NotContains(t, d, "groups")
	fetched := f.request("GET", "Users/"+d.Text("id"), "", "", 200)
	// Elimity validates against registered schemas and discards unknown attributes.
	require.NotContains(t, fetched, "urn:example:extension")
	f.request("PUT", "Users/"+d.Text("id"), user("subject", "alice", true), "", 200)
	fetched = f.request("GET", "Users/"+d.Text("id"), "", "", 200)
	require.NotContains(t, fetched, "urn:example:extension")
}

func TestCaseInsensitiveProvisioningAttributes(t *testing.T) {
	f := newFixture(t)
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"EXTERNALID":"subject","USERNAME":"alice","ACTIVE":true,"NAME":{"GIVENNAME":"Alice"},"EMAILS":[{"VALUE":"alice@example.test","PRIMARY":true}],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"DEPARTMENT":"Engineering","ORGANIZATION":"Example"}}`
	u := f.request("POST", "Users", body, "", 201)
	require.NotContains(t, u, "name")
	require.NotContains(t, u, "emails")
	require.Equal(t, "Engineering", f.facts("subject").Department)
	require.Equal(t, "Example", f.facts("subject").Organization)
	groupBody := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"DISPLAYNAME":"ops","MEMBERS":[{"VALUE":%q,"TYPE":"User"}]}`, u.Text("id"))
	f.request("POST", "Groups", groupBody, "", 201)
	require.Equal(t, []string{"ops"}, object.GroupNames(f.facts("subject").Facts().Groups))
}

func TestMinimalStoredProfileAndDiscovery(t *testing.T) {
	f := newFixture(t)
	const enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"externalId":"subject","userName":"alice","active":false,"userType":"employee","name":{"givenName":"Alice"},"emails":[{"value":"alice@example.test"}],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Engineering","organization":"Example","employeeNumber":"unused"}}`
	created := f.request("POST", "Users", body, "", 201)
	id := created.Text("id")
	stored, err := f.store.GetUser(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, "subject", stored.ExternalID)
	require.Equal(t, "employee", stored.UserType)
	require.Equal(t, "Engineering", stored.Department)
	require.Equal(t, "Example", stored.Organization)
	require.False(t, stored.Active)
	fetched := f.request("GET", "Users/"+id, "", "", 200)
	require.NotContains(t, fetched, "name")
	require.NotContains(t, fetched, "emails")
	require.JSONEq(t, `{"department":"Engineering","organization":"Example"}`, string(fetched[enterprise]))
	facts := f.facts("subject")
	require.Equal(t, stored.UserType, facts.UserType)
	require.Equal(t, stored.Department, facts.Department)
	require.Equal(t, stored.Organization, facts.Organization)

	// PUT removes omitted optional facts and applies the protocol's active default.
	f.request("PUT", "Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"subject","userName":"alice"}`, fetched.Version(), 200)
	replaced, err := f.store.GetUser(t.Context(), id)
	require.NoError(t, err)
	require.True(t, replaced.Active)
	require.Empty(t, replaced.UserType)
	require.Empty(t, replaced.Department)
	require.Empty(t, replaced.Organization)
	require.Equal(t, stored.Created, replaced.Created)
	require.NotEqual(t, replaced.Version, stored.Version)

	for _, tc := range []struct {
		schema string
		names  []string
	}{
		{userSchema, []string{"userName", "active", "userType", "password"}},
		{enterprise, []string{"department", "organization"}},
		{groupSchema, []string{"displayName", "members"}},
	} {
		discovery := f.request("GET", "Schemas/"+tc.schema, "", "", 200)
		var attrs []struct {
			Name string `json:"name"`
		}
		require.NoError(t, json.Unmarshal(discovery["attributes"], &attrs))
		var names []string
		for _, a := range attrs {
			names = append(names, a.Name)
		}
		require.ElementsMatch(t, tc.names, names)
	}
}

func TestConfiguredIdentityAssignment(t *testing.T) {
	const enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	for _, tc := range []struct {
		name, attribute, fields, want string
	}{
		{"default", "", `"externalId":"subject"`, "subject"},
		{"configured field wins", "USERname", `"externalId":"unrelated"`, "alice"},
		{"externalId optional", "userName", `"active":true`, "alice"},
		{"enterprise attribute", enterprise + ":department", `"` + enterprise + `":{"department":"mapped-subject"}`, "mapped-subject"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
			require.NoError(t, err)
			defer store.Close()
			handler, err := scim.NewBackend(store, tc.attribute)
			require.NoError(t, err)
			f := &fixture{t: t, store: store, handler: handler}
			body := fmt.Sprintf(`{"schemas":[%q,%q],"id":"forged","userName":"alice",%s}`, userSchema, enterprise, tc.fields)
			created := f.request("POST", "Users", body, "", 201)
			require.Equal(t, tc.want, created.Text("id"), "The configured attribute must determine ID; incoming id must be ignored")
			stored, err := store.GetUser(t.Context(), tc.want)
			require.NoError(t, err)
			require.NotNil(t, stored)
			require.NotNil(t, f.facts(tc.want), "Authentication and SCIM must use the same stored ID")
			replaced := f.request("PUT", "Users/"+tc.want, `{"schemas":["`+userSchema+`"],"id":"forged-again","userName":"renamed"}`, "", 200)
			require.Equal(t, tc.want, replaced.Text("id"), "Replacement must use the URL ID even when the source attribute changes or is omitted")
			require.NotNil(t, f.facts(tc.want))
			require.Nil(t, f.facts("renamed"))
		})
	}
}

func TestIdentityMappingRejectsInvalidConfigurationAndMissingValues(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer store.Close()
	for _, attribute := range []string{"id", "active", "missing", "emails.value"} {
		_, err := scim.NewBackend(store, attribute)
		require.ErrorContains(t, err, "unsupported SCIM user ID attribute", attribute)
	}
	handler, err := scim.NewBackend(store, "userType")
	require.NoError(t, err)
	f := &fixture{t: t, store: store, handler: handler}
	f.request("POST", "Users", user("not-a-fallback", "alice", true), "", 400)
	users, total, err := store.ListUsers(t.Context(), 1, 10)
	require.NoError(t, err)
	require.Zero(t, total, "Missing mapped identity must not create a resource")
	require.Empty(t, users)
}

func TestConditionalHTTPWrites(t *testing.T) {
	for _, kind := range []string{"Users", "Groups"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			body := group("ops")
			if kind == "Users" {
				body = user("subject", "alice", true)
			}
			created := f.request("POST", kind, body, "", 201)
			path := kind + "/" + created.Text("id")
			replaced := f.request("PUT", path, body, `W/"stale",  `+created.Version(), 200)
			require.NotEqual(t, created.Version(), replaced.Version())
			f.request("PUT", path, body, created.Version(), 412)
			f.request("DELETE", path, "", created.Version(), 412)
			f.request("PUT", path, body, "*", 200)
			f.request("DELETE", path, "", "*", 204)
			for _, match := range []string{"", "*", replaced.Version()} {
				f.request("PUT", path, body, match, 404)
				f.request("DELETE", path, "", match, 404)
			}
		})
	}
}

// Fixed unversioned records exercise protocol handling without a storage lifecycle.
type unversionedRecords struct {
	directory.Store
	user  directory.ManagedUser
	group directory.ManagedGroup
}

func (s unversionedRecords) SupportsVersioning() bool { return false }
func (s unversionedRecords) SupportsPatchUser() bool  { return false }
func (s unversionedRecords) SupportsPatchGroup() bool { return false }

func (s unversionedRecords) GetUser(context.Context, string) (*directory.ManagedUser, error) {
	return &s.user, nil
}

func (s unversionedRecords) GetGroup(context.Context, string) (*directory.ManagedGroup, error) {
	return &s.group, nil
}

func TestSCIMWithoutVersioning(t *testing.T) {
	store := unversionedRecords{
		user:  directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, UserName: "alice", Active: true},
		group: directory.ManagedGroup{Metadata: directory.Metadata{ID: "ops"}, DisplayName: "ops"},
	}
	handler, err := scim.NewBackend(store, "")
	require.NoError(t, err)
	f := &fixture{t: t, handler: handler}
	config := f.request("GET", "ServiceProviderConfig", "", "", 200)
	require.JSONEq(t, `{"supported":false}`, string(config["etag"]))
	for _, tc := range []struct{ path, body string }{
		{"Users/subject", user("subject", "alice", true)},
		{"Groups/ops", group("ops")},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/scim/v2/"+tc.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.Empty(t, w.Header().Get("ETag"))
			var record struct{ Meta map[string]json.RawMessage }
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &record))
			require.NotContains(t, record.Meta, "version")
			f := &fixture{t: t, handler: handler}
			// Specific ETags cannot match unversioned records; no write is reached.
			f.request("PUT", tc.path, tc.body, `W/"invented"`, 412)
			f.request("DELETE", tc.path, "", `W/"invented"`, 412)
		})
	}
}

// opaqueVersionStore exercises the adapter with a backend token that is neither
// numeric nor already an HTTP entity tag.
type opaqueVersionStore struct {
	directory.Store
	user     directory.ManagedUser
	expected string
	race     bool
}

func (s *opaqueVersionStore) SupportsVersioning() bool { return true }

func (s *opaqueVersionStore) SupportsPatchUser() bool  { return false }
func (s *opaqueVersionStore) SupportsPatchGroup() bool { return false }

func (s *opaqueVersionStore) GetUser(context.Context, string) (*directory.ManagedUser, error) {
	user := s.user
	return &user, nil
}

func (s *opaqueVersionStore) ReplaceUser(_ context.Context, user directory.ManagedUser, expectedVersion string, event directory.AuditEvent) (directory.ManagedUser, error) {
	s.expected = expectedVersion
	if s.race {
		s.user.Version = "concurrent-write"
	}
	if expectedVersion != "" && expectedVersion != s.user.Version {
		return directory.ManagedUser{}, directory.ErrVersion
	}
	user.Version = "next-opaque-token"
	s.user = user
	return user, nil
}

func TestOpaqueBackendVersions(t *testing.T) {
	const version = "backend/\"r, 2%雪"
	store := &opaqueVersionStore{user: directory.ManagedUser{
		Metadata: directory.Metadata{ID: "subject", Version: version},
		UserName: "alice", Active: true,
	}}
	handler, err := scim.NewBackend(store, "")
	require.NoError(t, err)
	f := &fixture{t: t, handler: handler}
	fetched := f.request("GET", "Users/subject", "", "", 200)
	tag := fetched.Version()
	require.NotEmpty(t, tag)
	require.NotContains(t, tag, ",", "Opaque tokens must be encoded safely inside HTTP entity tags")
	f.request("PUT", "Users/subject", user("subject", "renamed", true), `W/"stale", `+tag, 200)
	require.Equal(t, version, store.expected, "Storage must receive the original opaque token, without HTTP syntax")
	require.Equal(t, "renamed", store.user.UserName)

	// The read used to select a matching ETag must not weaken the write's CAS.
	tag = f.request("GET", "Users/subject", "", "", 200).Version()
	store.race = true
	f.request("PUT", "Users/subject", user("subject", "lost-update", true), tag, 412)
	require.Equal(t, "next-opaque-token", store.expected)
	require.Equal(t, "renamed", store.user.UserName)
}

func TestTimestampsAndAuditAssignedBeforeStorage(t *testing.T) {
	for _, kind := range []string{"Users", "Groups"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			body := group("ops")
			if kind == "Users" {
				body = user("subject", "alice", true)
			}
			// SCIM metadata is read-only: Epithet supplies both timestamps.
			body = strings.TrimSuffix(body, "}") + `,"meta":{"created":"2000-01-01T00:00:00Z","lastModified":"2000-01-01T00:00:00Z"}}`
			before := time.Now().UTC()
			created := f.request("POST", kind, body, "", 201)
			after := time.Now().UTC()
			id := created.Text("id")
			readMetadata := func() directory.Metadata {
				t.Helper()
				if kind == "Users" {
					stored, err := f.store.GetUser(t.Context(), id)
					require.NoError(t, err)
					require.NotNil(t, stored)
					return stored.Metadata
				}
				stored, err := f.store.GetGroup(t.Context(), id)
				require.NoError(t, err)
				require.NotNil(t, stored)
				return stored.Metadata
			}
			original := readMetadata()
			require.False(t, original.Created.Before(before), "SCIM must assign Created before calling storage")
			require.False(t, original.Created.After(after))
			require.True(t, original.Created.Equal(original.Modified), "Creation must supply identical Created and Modified")
			before = time.Now().UTC()
			f.request("PUT", kind+"/"+id, body, "", 200)
			after = time.Now().UTC()
			replaced := readMetadata()
			require.True(t, original.Created.Equal(replaced.Created), "Replacement must preserve the stored Created")
			require.False(t, replaced.Modified.Before(before), "SCIM must supply the replacement Modified")
			require.False(t, replaced.Modified.After(after))

			before = time.Now().UTC()
			f.request("DELETE", kind+"/"+id, "", "", 204)
			after = time.Now().UTC()
			events, _, err := f.store.Audit(t.Context(), "", 0)
			require.NoError(t, err)
			require.Len(t, events, 3)
			for i, action := range []string{"create", "replace", "delete"} {
				require.Equal(t, action, events[i].Action)
				require.Equal(t, id, events[i].ID)
				require.Equal(t, "scim", events[i].Actor)
			}
			require.True(t, original.Created.Equal(events[0].Time))
			require.True(t, replaced.Modified.Equal(events[1].Time))
			require.False(t, events[2].Time.Before(before))
			require.False(t, events[2].Time.After(after))
		})
	}
}

func TestReplacementIdentityComesFromURL(t *testing.T) {
	for _, kind := range []string{"Users", "Groups"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			body, otherBody := group("first"), group("other")
			if kind == "Users" {
				body, otherBody = user("subject", "alice", true), user("other-subject", "bob", true)
			}
			first := f.request("POST", kind, body, "", 201)
			other := f.request("POST", kind, otherBody, "", 201)
			otherID := other.Text("id")
			// SCIM id is read-only. The URL selects the replacement even when
			// the body includes a conflicting id.
			replacement := strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"id":%q}`, otherID)
			got := f.request("PUT", kind+"/"+first.Text("id"), replacement, first.Version(), 200)
			require.Equal(t, first.Text("id"), got.Text("id"))
			untouched := f.request("GET", kind+"/"+otherID, "", "", 200)
			require.Equal(t, other.Version(), untouched.Version(), "The body id must not redirect the write")
		})
	}
}

func TestInputValidationBeforeStorage(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.store.Close())
	// A storage call would fail. Invalid input must instead return 400 for
	// both creation and replacement, before any conditional read or mutation.
	for _, blank := range []string{"", " 	", " "} {
		for _, kind := range []string{"Users", "Groups"} {
			body := group(blank)
			if kind == "Users" {
				body = user("subject", blank, true)
			}
			f.request("POST", kind, body, "", 400)
			f.request("PUT", kind+"/subject", body, `W/"version"`, 400)
		}
	}
	f.request("POST", "Users", user(" 	", "alice", true), "", 400)
}

func TestUserNameUniquenessThroughSCIM(t *testing.T) {
	f := newFixture(t)
	first := f.request("POST", "Users", user("one", "Ａlice", false), "", 201)
	stored, err := f.store.GetUser(t.Context(), first.Text("id"))
	require.NoError(t, err)
	require.Equal(t, "Ａlice", stored.UserName)
	f.request("POST", "Users", user("duplicate", "ALICE", true), "", 409)
	second := f.request("POST", "Users", user("two", "Bob", true), "", 201)
	f.request("PUT", "Users/"+second.Text("id"), user("two", "aLiCe", true), "", 409)
	f.request("PUT", "Users/"+first.Text("id"), user("one", "Carol", true), "", 200)
	stored, err = f.store.GetUser(t.Context(), first.Text("id"))
	require.NoError(t, err)
	require.Equal(t, "Carol", stored.UserName)
	f.request("POST", "Users", user("three", "ALICE", true), "", 201)
}

// This backend only preserves the group it receives; it does not assign IDs.
type groupInputStore struct {
	directory.Store
	received directory.ManagedGroup
}

func (s *groupInputStore) SupportsVersioning() bool { return false }

func (s *groupInputStore) SupportsPatchUser() bool  { return false }
func (s *groupInputStore) SupportsPatchGroup() bool { return false }

func (s *groupInputStore) CreateGroup(_ context.Context, group directory.ManagedGroup, event directory.AuditEvent) (directory.ManagedGroup, error) {
	s.received = group
	return group, nil
}

func (s *groupInputStore) ReplaceGroup(_ context.Context, group directory.ManagedGroup, _ string, event directory.AuditEvent) (directory.ManagedGroup, error) {
	s.received = group
	return group, nil
}

func TestGroupMembershipDeduplicatedBeforeStorage(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "Groups", http.StatusCreated},
		{http.MethodPut, "Groups/existing", http.StatusOK},
	} {
		t.Run(tc.method, func(t *testing.T) {
			// This store preserves its input, so SQLite's membership constraint
			// cannot conceal a missing normalization step in the adapter.
			store := &groupInputStore{}
			handler, err := scim.NewBackend(store, "")
			require.NoError(t, err)
			f := &fixture{t: t, handler: handler}
			f.request(tc.method, tc.path, group("ops", "bob", "alice", "bob", "Alice", "alice"), "", tc.status)
			require.ElementsMatch(t, []string{"bob", "alice", "Alice"}, store.received.MemberIDs,
				"Storage must receive distinct IDs; identity comparison is case-sensitive")
		})
	}
}

func TestGroupIDAssignedBeforeStorage(t *testing.T) {
	store := &groupInputStore{}
	handler, err := scim.NewBackend(store, "")
	require.NoError(t, err)
	f := &fixture{t: t, handler: handler}
	body := strings.TrimSuffix(group("ops"), "}") + `,"id":"client-supplied"}`
	first := f.request("POST", "Groups", body, "", 201)
	require.NotEmpty(t, store.received.ID, "SCIM must assign an ID before calling CreateGroup")
	require.NotEqual(t, "client-supplied", store.received.ID, "SCIM id is read-only")
	require.Equal(t, store.received.ID, first.Text("id"))
	second := f.request("POST", "Groups", body, "", 201)
	require.Equal(t, store.received.ID, second.Text("id"))
	require.NotEqual(t, first.Text("id"), second.Text("id"), "Independent group creations must receive distinct IDs")
}
