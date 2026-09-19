package inventoryserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
	"github.com/epithet-ssh/epithet/pkg/inventoryserver"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestEnrollmentDecodesAccountRestrictions(t *testing.T) {
	store, err := inventory.OpenManaged(t.TempDir(), nil)
	require.NoError(t, err)
	defer store.Close()
	control := &inventoryserver.Control{Store: store}
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
			body := `{"action":"enroll","host":{"names":["host"],"principal-mode":"account-name"` + tc.field + `}}`
			request := httptest.NewRequest("POST", "/", strings.NewReader(body))
			response := httptest.NewRecorder()
			control.ServeHTTP(response, request)
			require.Equal(t, tc.status, response.Code, response.Body.String())
			if tc.status == 202 {
				var result inventoryapi.ControlResponse
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
				require.NotNil(t, result.Host)
				require.Equal(t, tc.want, result.Host.Proposal.Accounts)
			}
		})
	}
	hosts, err := store.List()
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
   groups: [ops]
 - id: directory-user
   userName: ordinary
 - id: directory-disabled
   userName: disabled
   active: false
   groups: [ops]
`), 0600))
	inv, err := inventory.NewStatic([]string{path})
	require.NoError(t, err)
	m, err := inventory.OpenManaged(t.TempDir(), inv)
	require.NoError(t, err)
	defer m.Close()
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(context.Background(), oidc.Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, UserIDClaim: "oid", TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	control := &inventoryserver.Control{Store: m, Directory: inv, Validator: validator, Admins: inventoryserver.Admins{Users: []string{"directory-admin"}, Groups: []string{"ops"}}}
	server := httptest.NewServer(control)
	defer server.Close()
	client, err := inventoryclient.New(server.URL+"?route=inventory", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for _, tc := range []struct {
		id   string
		want int
	}{{"directory-admin", 200}, {"directory-group", 200}, {"directory-user", 403}, {"directory-disabled", 403}, {"missing", 403}} {
		token := idp.MintIDTokenWithClaims("different-subject", time.Now().Add(time.Hour), map[string]any{"oid": tc.id})
		_, status, err := client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: "list"})
		require.Equal(t, tc.want, status)
		if status == 200 {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
	for _, token := range []string{"", "not-a-token", idp.MintIDTokenWithAudience("admin", "wrong-audience", time.Now().Add(time.Hour))} {
		_, status, err := client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: "list"})
		require.Equal(t, 401, status)
		require.Error(t, err)
	}
	p := inventoryapi.Proposal{Names: []string{"new-host"}, Accounts: []string{}, PrincipalMode: "account-name"}
	response, status, err := client.Control(t.Context(), "", inventoryapi.ControlRequest{Action: "enroll", Host: &p})
	require.NoError(t, err)
	require.Equal(t, 202, status)
	require.Equal(t, "pending", response.Host.Status)
	token := idp.MintIDTokenWithClaims("unrelated-subject", time.Now().Add(time.Hour), map[string]any{"oid": "directory-admin"})
	response, status, err = client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: "approve", ID: response.Host.ID, Revision: response.Host.Revision})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Equal(t, "active", response.Host.Status)
	audit, err := m.Audit()
	require.NoError(t, err)
	require.Equal(t, "directory-admin", audit[len(audit)-1].Actor)
}

func TestDirectoryUserListingAuthorizationAndSource(t *testing.T) {
	for _, source := range []string{"static", "scim"} {
		t.Run(source, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "static.yaml")
			require.NoError(t, os.WriteFile(path, []byte(`users:
 - id: subject:admin
   userName: admin
   groups: [wheel]
 - id: subject:ordinary
   userName: ordinary
 - id: subject:disabled
   userName: disabled
   active: false
   groups: [wheel]
`), 0600))
			static, err := inventory.NewStatic([]string{path})
			require.NoError(t, err)
			var selected directory.Directory = static
			var managed directory.Store
			if source == "scim" {
				store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
				require.NoError(t, err)
				defer store.Close()
				var members []string
				for _, name := range []string{"admin", "ordinary", "disabled"} {
					u, err := store.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "subject:" + name, UserName: name + "-scim", Active: name != "disabled"})
					require.NoError(t, err)
					if name != "ordinary" {
						members = append(members, u.ID)
					}
				}
				_, err = store.CreateGroup(t.Context(), directory.Group{DisplayName: "wheel", MemberIDs: members})
				require.NoError(t, err)
				selected, managed = store, store
			}
			idp := oidctest.New(t)
			validator, err := oidc.NewValidator(t.Context(), oidc.Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
			require.NoError(t, err)
			// No managed hosts: directory inspection must be independently available.
			control := &inventoryserver.Control{Directory: selected, ManagedDirectory: managed, Validator: validator, Admins: inventoryserver.Admins{Groups: []string{"wheel"}}}
			server := httptest.NewServer(control)
			defer server.Close()
			client, err := inventoryclient.New(server.URL, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			for _, tc := range []struct {
				name   string
				status int
			}{{"admin", 200}, {"ordinary", 403}, {"disabled", 403}, {"missing", 403}, {"", 401}} {
				token := ""
				if tc.name != "" {
					token = idp.MintIDToken(tc.name, time.Now().Add(time.Hour))
				}
				resp, status, err := client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: "directory-users"})
				require.Equal(t, tc.status, status)
				if tc.status != 200 {
					require.Error(t, err)
					continue
				}
				require.NoError(t, err)
				require.NotNil(t, resp.DirectoryUsers)
				require.NotEmpty(t, resp.DirectoryUsers.Revision)
				require.Len(t, resp.DirectoryUsers.Users, 3)
				admin := resp.DirectoryUsers.Users[0]
				require.Equal(t, "subject:admin", admin.ID)
				require.Equal(t, []string{"wheel"}, admin.Groups)
				wantName := "admin"
				if source == "scim" {
					wantName = "admin-scim"
				}
				require.Equal(t, wantName, admin.UserName)
				require.False(t, resp.DirectoryUsers.Users[1].Active)
			}
			_, status, err := client.Control(t.Context(), "", inventoryapi.ControlRequest{Action: "enroll"})
			require.Error(t, err)
			require.Equal(t, 404, status, "listing users must not enable host enrollment")
			if source == "static" {
				_, status, err = client.Control(t.Context(), idp.MintIDToken("admin", time.Now().Add(time.Hour)), inventoryapi.ControlRequest{Action: "directory-groups"})
				require.Error(t, err)
				require.Equal(t, 404, status, "SCIM binding operations stay unavailable in static mode")
			}
		})
	}
}

func TestDirectoryAuditCanBeReadBeyondControlResponseLimit(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "directory.db"))
	require.NoError(t, err)
	defer store.Close()
	_, err = store.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "subject:admin", UserName: "admin", Active: true})
	require.NoError(t, err)
	// Build a real audit history larger than the client allows in one response.
	// Names are retained on bind events; create events share their revisions.
	for n := 0; n < 500; n++ {
		_, err = store.CreateGroup(t.Context(), directory.Group{DisplayName: fmt.Sprintf("group-%d-", n) + strings.Repeat("x", 18<<10)})
		require.NoError(t, err)
	}
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(t.Context(), oidc.Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	control := &inventoryserver.Control{ManagedDirectory: store, Directory: store, Validator: validator, Admins: inventoryserver.Admins{Users: []string{"subject:admin"}}}
	server := httptest.NewServer(control)
	defer server.Close()
	client, err := inventoryclient.New(server.URL, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	token := idp.MintIDToken("admin", time.Now().Add(time.Hour))
	var after uint64
	var count, bytes int
	for {
		response, status, err := client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: "directory-audit", AuditAfter: after})
		require.NoError(t, err)
		require.Equal(t, 200, status)
		events := response.DirectoryAudit
		require.LessOrEqual(t, len(events), directory.DefaultAuditLimit)
		if len(events) == 0 {
			break
		}
		for _, event := range events {
			require.Equal(t, after+1, event.Sequence)
			after = event.Sequence
		}
		data, err := json.Marshal(events)
		require.NoError(t, err)
		bytes += len(data)
		count += len(events)
	}
	require.Equal(t, 1001, count)
	require.Greater(t, bytes, inventoryclient.MaxControlResponse)
	response, _, err := client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: "directory-audit", AuditLimit: 1})
	require.NoError(t, err)
	require.Len(t, response.DirectoryAudit, 1)
	_, status, err := client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: "directory-audit", AuditLimit: directory.MaxAuditLimit + 1})
	require.Error(t, err)
	require.Equal(t, 400, status)
	// Authorization is still required on every page.
	_, status, err = client.Control(t.Context(), "", inventoryapi.ControlRequest{Action: "directory-audit", AuditAfter: after})
	require.Error(t, err)
	require.Equal(t, 401, status)
}
