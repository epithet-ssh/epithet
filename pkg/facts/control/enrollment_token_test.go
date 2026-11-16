package control_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/control"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/test/controltest"
	"github.com/epithet-ssh/epithet/test/oidctest"
	"github.com/stretchr/testify/require"
)

func enrollmentCredential(t *testing.T, key sshcert.RawPrivateKey, subject string) string {
	t.Helper()
	s, err := control.New(control.Config{Key: key, DirectoryURL: "https://directory/lookup", InventoryBackendURL: "https://inventory/lookup", InventoryToken: "admin", Validator: &rejectingIdentity{}})
	require.NoError(t, err)
	body, err := json.Marshal(facts.ControlRequest{Action: "token-create", Subject: subject, LifetimeSeconds: 90 * 24 * 3600})
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/manage", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer admin")
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var result facts.ControlResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.NotNil(t, result.Token)
	return result.Token.Token
}

func TestEnrollmentCredentialScopeAndReuse(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(t.Context(), oidc.ValidatorConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	f := controltest.New(t, nil, nil, store, control.Config{InventoryToken: "inventory-secret", SCIMToken: "scim-secret", Validator: validator})
	client, err := facts.NewAdminClient(f.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	host := facts.InventoryInput{Names: []string{"*.build.example"}, Accounts: []string{}, PrincipalMode: "account-name"}
	for _, bearer := range []string{"", "wrong", "scim-secret", inventory.NewID()} {
		_, status, err := client.Control(t.Context(), bearer, facts.ControlRequest{Action: "create", ID: inventory.NewID(), Host: &host})
		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, status)
	}
	issued, _, err := client.Control(t.Context(), "inventory-secret", facts.ControlRequest{Action: "token-create", Subject: "provisioner", LifetimeSeconds: 90 * 24 * 3600})
	require.NoError(t, err)
	credential := issued.Token.Token
	id := inventory.NewID()
	result, status, err := client.Control(t.Context(), credential, facts.ControlRequest{Action: "create", ID: id, Host: &host})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Equal(t, inventory.StatusActive, result.Host.Status)
	require.Equal(t, id, result.Host.ID)
	retry, _, err := client.Control(t.Context(), "inventory-secret", facts.ControlRequest{Action: "create", ID: id, Host: &host})
	require.NoError(t, err)
	require.Equal(t, result, retry)
	host.Names = []string{"two.example"}
	host.Labels = map[string]string{"environment": "production"}
	host.Accounts = []string{"root", "deploy"}
	host.PrincipalMode, host.Realm = "epithet-principal-v1", "SuppliedRealm"
	_, status, err = client.Control(t.Context(), credential, facts.ControlRequest{Action: "create", ID: id, Host: &host})
	require.Error(t, err)
	require.Equal(t, 409, status)
	second, _, err := client.Control(t.Context(), credential, facts.ControlRequest{Action: "create", ID: inventory.NewID(), Host: &host})
	require.NoError(t, err)
	require.Equal(t, host, second.Host.Host)
	for _, action := range []string{"list", "get", "audit", "edit", "remove", "token-create", "directory-audit"} {
		_, status, err := client.Control(t.Context(), credential, facts.ControlRequest{Action: action, ID: id, ExpectedVersion: result.Host.Version, Host: &host, Subject: "other", LifetimeSeconds: 60})
		require.Error(t, err)
		require.Equal(t, http.StatusUnauthorized, status, action)
	}
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		req := httptest.NewRequest(method, "/scim/v2/Users", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+credential)
		response := httptest.NewRecorder()
		f.Control.ServeHTTP(response, req)
		require.Equal(t, http.StatusUnauthorized, response.Code)
	}
	for _, action := range []string{"approve", "deny", "token-revoke"} {
		_, status, err := client.Control(t.Context(), "inventory-secret", facts.ControlRequest{Action: action, ID: id})
		require.Error(t, err)
		require.Equal(t, 400, status)
	}
	// The former token-in-body protocol is rejected even with valid authentication.
	req := httptest.NewRequest("POST", "/manage/old", strings.NewReader(`{"id":"old","action":"create","token":"old"}`))
	req.Header.Set("Authorization", "Bearer "+credential)
	response := httptest.NewRecorder()
	f.Control.ServeHTTP(response, req)
	require.Equal(t, 400, response.Code)
	events, _, err := store.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Len(t, events, 2)
	for _, event := range events {
		require.Equal(t, "provisioner", event.Actor)
		require.Equal(t, "create", event.Action)
		require.NotContains(t, event.Resource, credential)
	}
}

func TestSubjectRevocationAndIssuanceValidation(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	f := controltest.New(t, nil, nil, store, control.Config{InventoryToken: "admin"})
	client, err := facts.NewAdminClient(f.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for _, request := range []facts.ControlRequest{
		{Action: "token-create"},
		{Action: "token-create", Subject: "provisioner"},
		{Action: "token-create", LifetimeSeconds: 60},
		{Action: "token-create", Subject: "provisioner", LifetimeSeconds: -1},
	} {
		_, status, err := client.Control(t.Context(), "admin", request)
		require.Error(t, err)
		require.Equal(t, 400, status)
	}
	for _, bearer := range []string{"", "wrong"} {
		_, status, err := client.Control(t.Context(), bearer, facts.ControlRequest{Action: "token-create", Subject: "provisioner", LifetimeSeconds: 60})
		require.Error(t, err)
		require.Equal(t, 401, status)
	}
	var credentials []string
	for _, seconds := range []int64{60, 90 * 24 * 3600} {
		issued, _, err := client.Control(t.Context(), "admin", facts.ControlRequest{Action: "token-create", Subject: "provisioner", LifetimeSeconds: seconds})
		require.NoError(t, err)
		credentials = append(credentials, issued.Token.Token)
	}
	host := facts.InventoryInput{Names: []string{"existing.example"}, Accounts: nil, PrincipalMode: "account-name"}
	existing, _, err := client.Control(t.Context(), credentials[0], facts.ControlRequest{Action: "create", ID: inventory.NewID(), Host: &host})
	require.NoError(t, err)
	// Restart control with the same key and an exact, case-sensitive denylist.
	restarted, err := control.New(control.Config{Key: f.ControlKey, DirectoryURL: f.DirectoryURL + "/lookup", InventoryBackendURL: f.InventoryURL, InventoryToken: "admin", Validator: &rejectingIdentity{}, DeniedSubjects: []string{"provisioner"}, TLS: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	server := httptest.NewServer(restarted)
	defer server.Close()
	denied, err := facts.NewAdminClient(server.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	for _, raw := range credentials {
		_, status, err := denied.Control(t.Context(), raw, facts.ControlRequest{Action: "create", ID: inventory.NewID(), Host: &host})
		require.Error(t, err)
		require.Equal(t, 403, status)
	}
	for _, subject := range []string{"provisioner", "Provisioner", "provisioner-new", "provisioner "} {
		issued, status, err := denied.Control(t.Context(), "admin", facts.ControlRequest{Action: "token-create", Subject: subject, LifetimeSeconds: 3600})
		if subject == "provisioner" {
			require.Error(t, err)
			require.Equal(t, 403, status)
			continue
		}
		require.NoError(t, err)
		host.Names = []string{"new-" + inventory.NewID()[:12] + ".example"}
		_, _, err = denied.Control(t.Context(), issued.Token.Token, facts.ControlRequest{Action: "create", ID: inventory.NewID(), Host: &host})
		require.NoError(t, err)
	}
	retained, err := store.GetHost(t.Context(), existing.Host.ID)
	require.NoError(t, err)
	require.Equal(t, "active", retained.Status)
	resolved, err := store.LookupHost(t.Context(), "existing.example")
	require.NoError(t, err)
	require.NotNil(t, resolved)
}

func TestCreateHostProviderBoundary(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(public, serviceauth.InventoryAudience)
	require.NoError(t, err)
	credential := enrollmentCredential(t, key, "provisioner")
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NotContains(t, r.Header.Get("Authorization"), credential)
		require.NotContains(t, string(body), credential)
		actor, err := verifier.VerifyActor(r, body)
		require.NoError(t, err)
		if r.Method == "OPTIONS" {
			w.Header().Set("Link-Template", `"/records{/id}"; rel="`+facts.InventoryRecordsRelation+`", "/audit"; rel="`+facts.InventoryAuditRelation+`"`)
			w.WriteHeader(204)
			return
		}
		require.Equal(t, "provisioner", actor)
		require.Equal(t, "POST", r.Method)
		var create facts.InventoryCreate
		require.NoError(t, facts.DecodeInventoryJSON(body, &create))
		require.Equal(t, []string{"Z.EXAMPLE", "a.example"}, create.Host.Name, "control must preserve provider input")
		w.Header().Set("ETag", `"1"`)
		json.NewEncoder(w).Encode(facts.InventoryRecord{ID: "created-host", Status: "active", Host: create.Host})
	}))
	defer provider.Close()
	s, err := control.New(control.Config{Key: key, DirectoryURL: provider.URL + "/directory", InventoryBackendURL: provider.URL + "/lookup", Validator: &rejectingIdentity{}, TLS: tlsconfig.Config{Insecure: true}})
	require.NoError(t, err)
	submit := func(id, header string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/manage/"+id, strings.NewReader(`{"id":"`+id+`","action":"create","host":{"names":["Z.EXAMPLE","a.example"],"principal-mode":"account-name","accounts":[]}}`))
		req.Header.Set("Authorization", header)
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		return response
	}
	for _, header := range []string{"", "Bearer wrong", "Basic " + credential, "Bearer " + credential + " extra"} {
		require.Equal(t, http.StatusUnauthorized, submit("created-host", header).Code)
	}
	require.Equal(t, http.StatusOK, submit("created-host", "Bearer "+credential).Code)
	// The provider always returns created-host, even for a different requested ID.
	mismatch := submit("another-host", "Bearer "+credential)
	require.Equal(t, http.StatusServiceUnavailable, mismatch.Code, mismatch.Body.String())
	var result facts.ControlResponse
	require.NoError(t, json.Unmarshal(mismatch.Body.Bytes(), &result))
	require.Nil(t, result.Host)
}

func TestConcurrentPublicEnrollmentIsCreationOnly(t *testing.T) {
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer store.Close()
	f := controltest.New(t, nil, nil, store, control.Config{})
	client, err := facts.NewAdminClient(f.URL+"/manage", tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	credential := enrollmentCredential(t, f.ControlKey, "provisioner")
	for _, identical := range []bool{true, false} {
		id := inventory.NewID()
		statuses := make(chan int, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Go(func() {
				name := "host-" + id[:12]
				if !identical && i == 1 {
					name += "-different"
				}
				host := facts.InventoryInput{Names: []string{name}, Accounts: []string{}, PrincipalMode: "account-name"}
				<-start
				_, status, _ := client.Control(t.Context(), credential, facts.ControlRequest{Action: "create", ID: id, Host: &host})
				statuses <- status
			})
		}
		close(start)
		wg.Wait()
		close(statuses)
		var actual []int
		for status := range statuses {
			actual = append(actual, status)
		}
		if identical {
			require.ElementsMatch(t, []int{200, 200}, actual)
		} else {
			require.ElementsMatch(t, []int{200, 409}, actual)
		}
	}
	events, _, err := store.Audit(t.Context(), "", 0)
	require.NoError(t, err)
	require.Len(t, events, 2)
}
