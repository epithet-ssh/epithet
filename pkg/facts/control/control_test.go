package control_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/control"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/test/controltest"
	"github.com/epithet-ssh/epithet/test/inventorytest"
	"github.com/epithet-ssh/epithet/test/oidctest"
	"github.com/stretchr/testify/require"
)

func TestEnrollmentDecodesAccountRestrictions(t *testing.T) {
	store, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	fixture := controltest.New(t, nil, nil, store, control.Config{EnrollmentToken: "enrollment-secret"})
	control := fixture.Control
	for _, tc := range []struct {
		field  string
		want   []string
		status int
	}{
		{"", nil, 400},
		{`,"accounts":"deploy"`, nil, 400},
		{`,"accounts":null`, nil, 202},
		{`,"accounts":[]`, []string{}, 202},
		{`,"accounts":["deploy"]`, []string{"deploy"}, 202},
	} {
		t.Run(tc.field, func(t *testing.T) {
			id := inventory.NewID()
			body := `{"id":"` + id + `","action":"enroll","host":{"names":["host"],"principal-mode":"account-name"` + tc.field + `}}`
			request := httptest.NewRequest("PUT", "/manage/"+id, strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer enrollment-secret")
			response := httptest.NewRecorder()
			control.ServeHTTP(response, request)
			require.Equal(t, tc.status, response.Code, response.Body.String())
			if tc.status == 202 {
				var result facts.ControlResponse
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
				require.NotNil(t, result.Host)
				require.Equal(t, tc.want, result.Host.Host.Accounts)
			}
		})
	}
	hosts, err := store.ListHosts(t.Context(), "", 0, false)
	require.NoError(t, err)
	require.Len(t, hosts, 3, "invalid input must never reach enrollment")
}

func TestControlUsesDirectoryIdentityAndAdminGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`users:
 - id: directory-admin
   userName: admin
 - id: directory-group
   userName: group-member
   groups: [{name: [ops]}]
 - id: directory-user
   userName: ordinary
 - id: directory-disabled
   userName: disabled
   active: false
   groups: [{name: [ops]}]
`), 0600))
	inv, err := inventorytest.NewStatic([]string{path})
	require.NoError(t, err)
	m, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer m.Close()
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(context.Background(), oidc.ValidatorConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, UserIDClaim: "oid", TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	server := controltest.New(t, inv, nil, m, control.Config{Validator: validator, InventoryAdmins: control.Admins{Users: []string{"directory-admin"}, Groups: []string{"ops"}}, EnrollmentToken: "enrollment-secret"})
	client, err := facts.NewAdminClient(server.URL+"/manage?route=inventory", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for _, tc := range []struct {
		id   string
		want int
	}{{"directory-admin", 200}, {"directory-group", 200}, {"directory-user", 403}, {"directory-disabled", 403}, {"missing", 403}} {
		token := idp.MintIDTokenWithClaims("different-subject", time.Now().Add(time.Hour), map[string]any{"oid": tc.id})
		_, status, err := client.Control(t.Context(), token, facts.ControlRequest{Action: "list"})
		require.Equal(t, tc.want, status)
		if status == 200 {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
	for _, token := range []string{"", "not-a-token", idp.MintIDTokenWithAudience("admin", "wrong-audience", time.Now().Add(time.Hour))} {
		_, status, err := client.Control(t.Context(), token, facts.ControlRequest{Action: "list"})
		require.Equal(t, 401, status)
		require.Error(t, err)
	}
	p := facts.InventoryInput{Names: []string{"new-host"}, Accounts: []string{}, PrincipalMode: "account-name"}
	response, status, err := client.Control(t.Context(), "enrollment-secret", facts.ControlRequest{Action: "enroll", ID: inventory.NewID(), Host: &p})
	require.NoError(t, err)
	require.Equal(t, 202, status)
	require.Equal(t, "pending", response.Host.Status)
	token := idp.MintIDTokenWithClaims("unrelated-subject", time.Now().Add(time.Hour), map[string]any{"oid": "directory-admin"})
	response, status, err = client.Control(t.Context(), token, facts.ControlRequest{Action: "approve", ID: response.Host.ID, ExpectedVersion: response.Host.Version})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Equal(t, "active", response.Host.Status)
	audit, _, err := m.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Equal(t, "directory-admin", audit[len(audit)-1].Actor)
	pattern := facts.InventoryInput{Names: []string{"ci-*.example"}, Accounts: []string{"root"}, PrincipalMode: "epithet-principal-v1", Realm: "CIRunners"}
	for _, tc := range []struct {
		id   string
		want int
	}{{"", 401}, {"directory-user", 403}, {"directory-disabled", 403}, {"directory-admin", 200}} {
		bearer := ""
		if tc.id != "" {
			bearer = idp.MintIDTokenWithClaims("unrelated-subject", time.Now().Add(time.Hour), map[string]any{"oid": tc.id})
		}
		result, status, err := client.Control(t.Context(), bearer, facts.ControlRequest{Action: "add", Host: &pattern})
		require.Equal(t, tc.want, status)
		if status == 200 {
			require.NoError(t, err)
			require.Equal(t, "active", result.Host.Status)
			require.Equal(t, "CIRunners", result.Host.Host.Realm)
			require.Equal(t, pattern.Names, result.Host.Host.Names)
		} else {
			require.Error(t, err)
		}
	}

}

func TestDirectoryUserListingAuthorizationAndSource(t *testing.T) {
	for _, source := range []string{"static", "scim"} {
		t.Run(source, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "static.yaml")
			require.NoError(t, os.WriteFile(path, []byte(`users:
 - id: subject:admin
   userName: admin
   groups: [{name: [wheel]}]
 - id: subject:ordinary
   userName: ordinary
 - id: subject:disabled
   userName: disabled
   active: false
   groups: [{name: [wheel]}]
`), 0600))
			static, err := inventorytest.NewStatic([]string{path})
			require.NoError(t, err)
			var selected directory.Directory = static
			var managed directory.Store
			if source == "scim" {
				store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
				require.NoError(t, err)
				defer store.Close()
				var members []string
				for _, name := range []string{"admin", "ordinary", "disabled"} {
					u, err := store.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject:" + name}, ExternalID: "subject:" + name, UserName: name + "-scim", Active: name != "disabled"}, directory.NewAuditEvent(t.Context(), "create", "subject:"+name))
					require.NoError(t, err)
					if name != "ordinary" {
						members = append(members, u.ID)
					}
				}
				_, err = store.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-wheel"}, DisplayName: "wheel", MemberIDs: members}, directory.NewAuditEvent(t.Context(), "create", "group-wheel"))
				require.NoError(t, err)
				selected, managed = store, store
			}
			idp := oidctest.New(t)
			validator, err := oidc.NewValidator(t.Context(), oidc.ValidatorConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
			require.NoError(t, err)
			// No managed hosts: directory inspection must be independently available.
			server := controltest.New(t, selected, managed, nil, control.Config{Validator: validator, DirectoryAdmins: control.Admins{Groups: []string{"wheel"}}})
			client, err := facts.NewAdminClient(server.URL+"/manage", tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			for _, tc := range []struct {
				name   string
				status int
			}{{"admin", 200}, {"ordinary", 403}, {"disabled", 403}, {"missing", 403}, {"", 401}} {
				token := ""
				if tc.name != "" {
					token = idp.MintIDToken(tc.name, time.Now().Add(time.Hour))
				}
				resp, status, err := client.ListUsers(t.Context(), token, 1)
				if source == "static" && tc.name == "admin" {
					tc.status = 404
				}
				require.Equal(t, tc.status, status)
				if tc.status != 200 {
					require.Error(t, err)
					continue
				}
				require.NoError(t, err)
				require.Len(t, resp.Resources, 3)
				require.Equal(t, 3, resp.TotalResults)
				byName := map[string]map[string]any{}
				for _, raw := range resp.Resources {
					var user map[string]any
					require.NoError(t, json.Unmarshal(raw, &user))
					byName[user["userName"].(string)] = user
				}
				require.Equal(t, "subject:admin", byName["admin-scim"]["externalId"])
				require.Equal(t, "subject:admin", byName["admin-scim"]["id"])
				require.Equal(t, false, byName["disabled-scim"]["active"])
			}
			_, status, err := client.Control(t.Context(), "", facts.ControlRequest{Action: "enroll", ID: inventory.NewID()})
			require.Error(t, err)
			require.Equal(t, 404, status, "listing users must not enable host enrollment")
			if source == "static" {
				_, status, err = client.ListGroups(t.Context(), idp.MintIDToken("admin", time.Now().Add(time.Hour)), 1)
				require.Error(t, err)
				require.Equal(t, 404, status, "SCIM group listing stays unavailable in static mode")
			}
		})
	}
}

func TestDirectoryAuditCanBeReadBeyondControlResponseLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := sqlitestore.Open(path)
	require.NoError(t, err)
	defer store.Close()
	_, err = store.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject:admin"}, ExternalID: "subject:admin", UserName: "admin", Active: true}, directory.NewAuditEvent(t.Context(), "create", "subject:admin"))
	require.NoError(t, err)
	// Retained historical binding events can exceed a single response limit.
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	for range 1000 {
		_, err = db.Exec(`INSERT INTO audit (time,actor,action,resource_id,alias,previous_id) VALUES (?,'scim','bind','g',?,'')`, time.Now().UTC().Format(time.RFC3339Nano), strings.Repeat("x", 9<<10))
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(t.Context(), oidc.ValidatorConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	server := controltest.New(t, store, store, nil, control.Config{Validator: validator, DirectoryAdmins: control.Admins{Users: []string{"subject:admin"}}})
	client, err := facts.NewAdminClient(server.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	token := idp.MintIDToken("admin", time.Now().Add(time.Hour))
	var cursor string
	var count, bytes int
	for {
		response, status, err := client.Control(t.Context(), token, facts.ControlRequest{Action: "directory-audit", AuditCursor: cursor})
		require.NoError(t, err)
		require.Equal(t, 200, status)
		events := response.DirectoryAudit.Events
		require.LessOrEqual(t, len(events), directory.DefaultAuditLimit)
		data, err := json.Marshal(events)
		require.NoError(t, err)
		bytes += len(data)
		count += len(events)
		cursor = response.DirectoryAudit.Next
		if cursor == "" {
			break
		}
	}
	require.Equal(t, 1001, count)
	require.Greater(t, bytes, facts.MaxControlResponse)
	response, _, err := client.Control(t.Context(), token, facts.ControlRequest{Action: "directory-audit", AuditLimit: 1})
	require.NoError(t, err)
	require.Len(t, response.DirectoryAudit.Events, 1)
	_, status, err := client.Control(t.Context(), token, facts.ControlRequest{Action: "directory-audit", AuditLimit: directory.MaxAuditLimit + 1})
	require.Error(t, err)
	require.Equal(t, 400, status)
	// Authorization is still required on every page.
	_, status, err = client.Control(t.Context(), "", facts.ControlRequest{Action: "directory-audit", AuditCursor: cursor})
	require.Error(t, err)
	require.Equal(t, 401, status)
}

func TestInventoryPaginationThroughPublicControl(t *testing.T) {
	users, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer users.Close()
	_, err = users.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject:admin"}, ExternalID: "subject:admin", UserName: "admin", Active: true}, directory.NewAuditEvent(t.Context(), "create", "subject:admin"))
	require.NoError(t, err)
	hosts, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer hosts.Close()
	// The total audit exceeds the transport cap; each default page fits. The
	// real stores and both HTTP planes must preserve cursors and page limits.
	for n := 0; n < 130; n++ {
		id1 := inventory.NewID()
		_, err = hosts.UpsertHost(t.Context(), inventory.Host{ID: id1, Status: inventory.StatusPending, Names: []string{"host"}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}, inventory.WriteConditions{}, inventory.NewAuditEvent(strings.Repeat("x", 70<<10), "enroll", id1))
		require.NoError(t, err)
	}
	first, err := hosts.ListHosts(t.Context(), "", 1, false)
	require.NoError(t, err)
	p := inventory.Host{Names: []string{"host"}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
	first[0].Names, first[0].Accounts, first[0].PrincipalMode = p.Names, p.Accounts, p.PrincipalMode
	h, err := hosts.UpsertHost(t.Context(), first[0], inventory.WriteConditions{ExpectedVersion: first[0].Version}, inventory.NewAuditEvent("admin", "edit", (first[0]).ID))
	require.NoError(t, err)
	h.Status = "active"
	_, err = hosts.UpsertHost(t.Context(), *h, inventory.WriteConditions{ExpectedVersion: h.Version}, inventory.NewAuditEvent("admin", "edit", h.ID))
	require.NoError(t, err)
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(t.Context(), oidc.ValidatorConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	server := controltest.New(t, users, users, hosts, control.Config{Validator: validator, InventoryAdmins: control.Admins{Users: []string{"subject:admin"}}})
	client, err := facts.NewAdminClient(server.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	token := idp.MintIDToken("admin", time.Now().Add(time.Hour))
	var cursor string
	var count, bytes int
	for {
		r, _, err := client.Control(t.Context(), token, facts.ControlRequest{Action: "audit", AuditCursor: cursor})
		require.NoError(t, err)
		require.LessOrEqual(t, len(r.Audit.Events), inventory.DefaultPageLimit)
		data, err := json.Marshal(r.Audit.Events)
		require.NoError(t, err)
		bytes += len(data)
		count += len(r.Audit.Events)
		cursor = r.Audit.Next
		if cursor == "" {
			break
		}
	}
	require.Equal(t, 132, count)
	require.Greater(t, bytes, facts.MaxControlResponse)
	for _, action := range []string{"list"} {
		var after string
		count := 0
		for {
			r, _, err := client.Control(t.Context(), token, facts.ControlRequest{Action: action, After: after, Limit: 37})
			require.NoError(t, err)
			var ids []string
			for _, h := range r.Hosts {
				ids = append(ids, h.ID)
			}
			require.LessOrEqual(t, len(ids), 37)
			if len(ids) == 0 {
				break
			}
			for _, id := range ids {
				require.Greater(t, id, after)
				after = id
			}
			count += len(ids)
		}
		require.Equal(t, 130, count)
		_, status, err := client.Control(t.Context(), "", facts.ControlRequest{Action: action, After: after})
		require.Error(t, err)
		require.Equal(t, 401, status)
	}
	r, _, err := client.Control(t.Context(), token, facts.ControlRequest{Action: "list", Pending: true, Limit: 3})
	require.NoError(t, err)
	require.Len(t, r.Hosts, 3)
	for _, h := range r.Hosts {
		require.Equal(t, "pending", h.Status)
	}
	for _, req := range []facts.ControlRequest{
		{Action: "audit", AuditLimit: inventory.MaxPageLimit + 1},
		{Action: "audit", AuditLimit: -1},
		{Action: "list", Limit: inventory.MaxPageLimit + 1},
		{Action: "token-list", Limit: -1},
		{Action: "list", After: "short"},
	} {
		_, status, err := client.Control(t.Context(), token, req)
		require.Error(t, err)
		require.Equal(t, 400, status)
	}
}
