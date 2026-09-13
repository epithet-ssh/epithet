package inventoryserver_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	p := inventory.Proposal{Names: []string{"new-host"}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
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
