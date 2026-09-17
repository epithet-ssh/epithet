package scim_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/directory/scim"
	"github.com/epithet-ssh/epithet/pkg/directory/sqlitestore"
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

type fixture struct {
	t       *testing.T
	store   *sqlitestore.Store
	handler *scim.Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s, e := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, e)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	h, e := scim.New(s, "provisioning-secret")
	require.NoError(t, e)
	return &fixture{t, s, h}
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
	u, rev, e := f.store.LookupUser(f.t.Context(), id)
	require.NoError(f.t, e)
	require.NotEmpty(f.t, rev)
	return u
}

func TestProvisioningLifecycleAndGroupBindings(t *testing.T) {
	f := newFixture(t)
	a := f.request("POST", "Users", user("sub-alice", "alice", true), "", 201).Text("id")
	b := f.request("POST", "Users", user("sub-bob", "bob", true), "", 201).Text("id")
	require.NotEqual(t, "sub-alice", a)
	require.Nil(t, f.facts(a))
	require.Nil(t, f.facts("alice"))
	g := f.request("POST", "Groups", group("ops", a), "", 201).Text("id")
	duplicate := f.request("POST", "Groups", group("ops", b), "", 201).Text("id")
	require.Equal(t, []string{"ops"}, f.facts("sub-alice").Groups)
	require.Empty(t, f.facts("sub-bob").Groups)
	snapshot, e := f.store.Bindings(t.Context())
	require.NoError(t, e)
	require.Len(t, snapshot.Groups, 2)
	for _, v := range snapshot.Groups {
		if v.ID == duplicate {
			require.Equal(t, "conflict", v.Status)
		}
	}
	f.request("PUT", "Groups/"+g, group("renamed", a), "", 200)
	require.Equal(t, []string{"ops"}, f.facts("sub-alice").Groups)
	// Deactivation retains membership; a trusted identity change transfers that same resource.
	f.request("PUT", "Users/"+a, user("sub-new", "renamed-alice", false), "", 200)
	require.Nil(t, f.facts("sub-alice"))
	require.False(t, f.facts("sub-new").Active)
	require.Equal(t, []string{"ops"}, f.facts("sub-new").Groups)
	f.request("PUT", "Users/"+a, user("sub-new", "renamed-alice", true), "", 200)
	f.request("DELETE", "Groups/"+g, "", "", 204)
	replacement := f.request("POST", "Groups", group("ops", a), "", 201).Text("id")
	require.Empty(t, f.facts("sub-new").Groups)
	require.ErrorIs(t, f.store.Rebind(t.Context(), "admin-sub", "ops", replacement, snapshot.Revision, f.revision()), directory.ErrVersion)
	snapshot, e = f.store.Bindings(t.Context())
	require.NoError(t, e)
	require.NoError(t, f.store.Rebind(t.Context(), "admin-sub", "ops", replacement, snapshot.Revision, f.revision()))
	require.Equal(t, []string{"ops"}, f.facts("sub-new").Groups)
	require.Empty(t, f.facts("sub-bob").Groups)
	events, e := f.store.Audit(t.Context(), 0, 0)
	require.NoError(t, e)
	last := events[len(events)-1]
	require.Equal(t, "admin-sub", last.Actor)
	require.Equal(t, g, last.PreviousID)
	require.Equal(t, "rebind", last.Action)
	found := false
	for _, v := range events {
		found = found || v.Action == "name-conflict"
	}
	require.True(t, found)
	before, e := f.store.GetGroup(t.Context(), replacement)
	require.NoError(t, e)
	f.request("DELETE", "Users/"+a, "", "", 204)
	f.request("GET", "Users/"+a, "", "", 404)
	require.Nil(t, f.facts("sub-new"))
	after, e := f.store.GetGroup(t.Context(), replacement)
	require.NoError(t, e)
	require.Empty(t, after.MemberIDs)
	require.Greater(t, after.Version, before.Version)
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
	old, e := f.store.GetUser(t.Context(), a)
	require.NoError(t, e)
	f.request("PUT", "Users/"+a, user("alice-sub", "Renamed", true), old.ETag(), 200)
	f.request("PUT", "Users/"+a, user("alice-sub", "stale", true), old.ETag(), 412)
	f.request("DELETE", "Users/"+a, "", old.ETag(), 412)
	require.Equal(t, "Renamed", f.facts("alice-sub").UserName)
	snapshot, e := f.store.Bindings(t.Context())
	require.NoError(t, e)
	f.request("POST", "Groups", group("bad", a, "missing"), "", 400)
	next, e := f.store.Bindings(t.Context())
	require.NoError(t, e)
	require.Equal(t, snapshot, next)
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
	f.request("PATCH", "Users/"+a, `{}`, "", 405)
	config := f.request("GET", "ServiceProviderConfig", "", "", 200)
	require.JSONEq(t, `{"supported":false}`, string(config["patch"]))
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

func (f *fixture) revision() directory.Revision {
	f.t.Helper()
	_, rev, e := f.store.LookupUser(f.t.Context(), "unused")
	require.NoError(f.t, e)
	return rev
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
	require.Equal(t, []string{"ops"}, f.facts("subject").Groups)
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
	f.request("PUT", "Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"subject","userName":"alice"}`, stored.ETag(), 200)
	replaced, err := f.store.GetUser(t.Context(), id)
	require.NoError(t, err)
	require.True(t, replaced.Active)
	require.Empty(t, replaced.UserType)
	require.Empty(t, replaced.Department)
	require.Empty(t, replaced.Organization)
	require.Equal(t, stored.Created, replaced.Created)
	require.Greater(t, replaced.Version, stored.Version)

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
