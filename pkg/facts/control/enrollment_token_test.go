package control_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/control"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/test/controltest"
	"github.com/stretchr/testify/require"
)

func TestEnrollmentBearerScope(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	validator := &rejectingIdentity{}
	f := controltest.New(t, nil, nil, store, control.Config{
		EnrollmentToken: "enrollment-secret", InventoryToken: "inventory-secret", SCIMToken: "scim-secret", Validator: validator,
	})
	client, err := facts.NewAdminClient(f.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	host := facts.InventoryInput{Names: []string{"pending.example"}, Accounts: []string{}, PrincipalMode: "account-name"}
	for _, bearer := range []string{"", "wrong", "inventory-secret", "scim-secret"} {
		_, status, err := client.Control(t.Context(), bearer, facts.ControlRequest{Action: "enroll", ID: inventory.NewID(), Host: &host})
		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, status)
	}
	hosts, err := store.ListHosts(t.Context(), "", 0, false)
	require.NoError(t, err)
	require.Empty(t, hosts)
	events, _, err := store.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Empty(t, events)
	result, status, err := client.Control(t.Context(), "enrollment-secret", facts.ControlRequest{Action: "enroll", ID: inventory.NewID(), Host: &host})
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, status)
	require.Equal(t, inventory.StatusPending, result.Host.Status)
	resolved, err := store.LookupHost(t.Context(), "pending.example")
	require.NoError(t, err)
	require.Nil(t, resolved)
	for _, action := range []string{"list", "get", "audit", "add", "edit", "remove", "approve", "deny", "token-create", "token-revoke", "directory-audit"} {
		t.Run(action, func(t *testing.T) {
			_, status, err := client.Control(t.Context(), "enrollment-secret", facts.ControlRequest{Action: action, ID: result.Host.ID, ExpectedVersion: result.Host.Version, Host: &host})
			require.Error(t, err)
			require.Equal(t, http.StatusForbidden, status)
		})
	}
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		req := httptest.NewRequest(method, "/scim/v2/Users", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer enrollment-secret")
		response := httptest.NewRecorder()
		f.Control.ServeHTTP(response, req)
		require.Equal(t, http.StatusForbidden, response.Code)
	}
	require.Zero(t, validator.calls, "enrollment credentials must never fall through to OIDC authorization")
	unchanged, err := store.GetHost(t.Context(), result.Host.ID)
	require.NoError(t, err)
	require.Equal(t, inventory.StatusPending, unchanged.Status)
	events, _, err = store.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Len(t, events, 1, "only the pending enrollment may mutate inventory")
	// Supplying a bogus single-use credential must not bypass the gate to create
	// a pending record. A real credential still permits preapproved enrollment.
	_, status, err = client.Control(t.Context(), "", facts.ControlRequest{Action: "enroll", Host: &host, Token: inventory.NewID()})
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, status)
	credential, _, err := client.Control(t.Context(), "inventory-secret", facts.ControlRequest{Action: "token-create"})
	require.NoError(t, err)
	active, _, err := client.Control(t.Context(), "", facts.ControlRequest{Action: "enroll", Host: &host, Token: credential.Token.ID})
	require.NoError(t, err)
	require.Equal(t, inventory.StatusActive, active.Host.Status)
}

func TestEnrollmentBearerStopsAtControl(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(public, serviceauth.InventoryAudience)
	require.NoError(t, err)
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotContains(t, r.Header.Get("Authorization"), "enrollment-secret")
		require.NotContains(t, string(body), "enrollment-secret")
		actor, err := verifier.VerifyActor(r, body)
		require.NoError(t, err, "provider receives control's signed credential")
		require.Empty(t, actor, "enrollment must not become an administrator write")
		if r.Method == "OPTIONS" {
			w.Header().Set("Link-Template", `"/records{/id}"; rel="`+facts.InventoryRecordsRelation+`", "/tokens"; rel="`+facts.InventoryTokensRelation+`", "/audit"; rel="`+facts.InventoryAuditRelation+`"`)
			w.WriteHeader(204)
			return
		}
		require.Equal(t, "/records/created-host", r.URL.Path)
		require.Equal(t, "PUT", r.Method)
		var create facts.InventoryCreate
		require.NoError(t, json.Unmarshal(body, &create))
		require.Empty(t, create.Token, "shared bearer must not become a single-use token")
		w.Header().Set("ETag", `"1"`)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(facts.InventoryRecord{ID: "created-host", Status: "pending", Host: create.Host})
	}))
	defer provider.Close()
	for _, configured := range []string{"", "enrollment-secret"} {
		s, err := control.New(control.Config{Key: key, DirectoryURL: provider.URL + "/directory", InventoryBackendURL: provider.URL + "/lookup", Validator: &rejectingIdentity{}, EnrollmentToken: configured, TLS: tlsconfig.Config{Insecure: true}})
		require.NoError(t, err)
		for _, header := range []string{"", "Bearer wrong", "Basic enrollment-secret", "Bearer enrollment-secret extra", "Bearer enrollment-secret"} {
			before := calls.Load()
			req := httptest.NewRequest("PUT", "/manage/created-host", strings.NewReader(`{"id":"created-host","action":"enroll","host":{"names":["pending.example"],"principal-mode":"account-name","accounts":[]}}`))
			req.Header.Set("Authorization", header)
			response := httptest.NewRecorder()
			s.ServeHTTP(response, req)
			if configured != "" && header == "Bearer enrollment-secret" {
				require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
				require.EqualValues(t, 2, calls.Load()-before)
			} else {
				require.Equal(t, http.StatusUnauthorized, response.Code)
				require.Equal(t, `Bearer realm="enrollment"`, response.Header().Get("WWW-Authenticate"))
				require.Equal(t, before, calls.Load(), "unauthorized enrollment must not contact inventory")
			}
		}
	}
}
