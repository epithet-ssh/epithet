package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
)

func TestInventoryRESTLifecycle(t *testing.T) {
	ca, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	store, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	handler, err := factserver.InventoryHandler(store, ca, pub, factserver.WithInventoryManagement(store))
	require.NoError(t, err)
	signer, err := serviceauth.NewSignerFor(key, serviceauth.InventoryAudience)
	require.NoError(t, err)
	call := func(method, path, actor, match string, input any) *httptest.ResponseRecorder {
		var body []byte
		if input != nil {
			body, err = json.Marshal(input)
			require.NoError(t, err)
		}
		req := httptest.NewRequest(method, "http://inventory"+path, bytes.NewReader(body))
		req.Header.Set("If-Match", match)
		require.NoError(t, signer.AuthorizeActor(req, body, actor))
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	decode := func(out *httptest.ResponseRecorder) facts.InventoryRecord {
		var h facts.InventoryRecord
		require.NoError(t, json.Unmarshal(out.Body.Bytes(), &h))
		return h
	}
	options := call("OPTIONS", "/lookup", "", "", nil)
	require.Equal(t, 204, options.Code)
	require.Len(t, options.Header().Values("Link-Template"), 3)
	host := &facts.InventoryHost{Name: []string{"one.example"}, Accounts: []string{}, Principal: facts.InventoryPrincipal{Mode: "account-name"}}
	created := call("POST", "/inventory/records", "", "", facts.InventoryCreate{Host: host})
	require.Equal(t, 201, created.Code, created.Body.String())
	h := decode(created)
	require.Equal(t, "pending", h.Status)
	require.Equal(t, `"1"`, created.Header().Get("ETag"))
	require.NotContains(t, created.Body.String(), `"revision"`)
	path := created.Header().Get("Location")
	require.Equal(t, 403, call("GET", path, "", "", nil).Code)
	require.Equal(t, 428, call("PUT", path, "admin", "", h).Code)
	// Changing both the specification and status cannot approve unseen edits.
	h.Status = "active"
	h.Host.Attributes = map[string]string{"environment": "prod"}
	require.Equal(t, 400, call("PUT", path, "admin", `"1"`, h).Code)
	h.Host.Attributes = nil
	approved := call("PUT", path, "admin", `"1"`, h)
	require.Equal(t, 200, approved.Code, approved.Body.String())
	require.Equal(t, `"2"`, approved.Header().Get("ETag"))
	require.Equal(t, 412, call("PUT", path, "admin", `"1"`, h).Code)
	h = decode(approved)
	h.CreatedAt = h.CreatedAt.Add(1)
	require.Equal(t, 400, call("PUT", path, "admin", `"2"`, h).Code)
	h = decode(approved)
	require.NotNil(t, h.Host.Accounts)
	require.Empty(t, h.Host.Accounts)
	require.Equal(t, 412, call("DELETE", path, "admin", `"1"`, nil).Code)
	// If-Match is covered by the service signature; changing it is not a write.
	req := httptest.NewRequest("DELETE", "http://inventory"+path, nil)
	req.Header.Set("If-Match", `"1"`)
	require.NoError(t, signer.AuthorizeActor(req, nil, "admin"))
	req.Header.Set("If-Match", `"2"`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, 403, rec.Code)
	require.Equal(t, 204, call("DELETE", path, "admin", `"2"`, nil).Code)
	require.Equal(t, 404, call("GET", path, "admin", "", nil).Code)
	// The token is returned at creation, never through a GET or listing.
	tokenResponse := call("POST", "/inventory/tokens", "admin", "", facts.InventoryTokenCreate{LifetimeSeconds: 60})
	require.Equal(t, 201, tokenResponse.Code)
	var token facts.InventoryToken
	require.NoError(t, json.Unmarshal(tokenResponse.Body.Bytes(), &token))
	require.Equal(t, 405, call("GET", "/inventory/tokens", "admin", "", nil).Code)
	require.Equal(t, 405, call("GET", "/inventory/tokens?token="+token.Token, "admin", "", nil).Code)
	reserved := call("GET", "/inventory/records/"+token.Token, "admin", "", nil)
	require.Nil(t, decode(reserved).Host)
	admitted := call("POST", "/inventory/records", "", "", facts.InventoryCreate{Host: host, Token: token.Token})
	require.Equal(t, 200, admitted.Code, admitted.Body.String())
	require.Equal(t, token.Token, decode(admitted).ID)
	require.Equal(t, 403, call("POST", "/inventory/records", "", "", facts.InventoryCreate{Host: host, Token: token.Token}).Code)
	require.Equal(t, 204, call("DELETE", "/inventory/tokens?token="+token.Token, "admin", "", nil).Code)
	// Empty reservations can be denied without supplying host attributes.
	tokenResponse = call("POST", "/inventory/tokens", "admin", "", facts.InventoryTokenCreate{})
	require.NoError(t, json.Unmarshal(tokenResponse.Body.Bytes(), &token))
	reserved = call("GET", "/inventory/records/"+token.Token, "admin", "", nil)
	h = decode(reserved)
	h.Status = "denied"
	denied := call("PUT", "/inventory/records/"+token.Token, "admin", reserved.Header().Get("ETag"), h)
	require.Equal(t, 200, denied.Code, denied.Body.String())
	require.Nil(t, decode(denied).Host)
	// A pattern is still an enrollment proposal unless an admin is authenticated.
	pattern := &facts.InventoryHost{Pattern: "*.example", Accounts: nil, Principal: facts.InventoryPrincipal{Mode: "account-name"}}
	pending := call("POST", "/inventory/records", "", "", facts.InventoryCreate{Host: pattern})
	require.Equal(t, 201, pending.Code)
	require.Equal(t, "pending", decode(pending).Status)
	active := call("POST", "/inventory/records", "admin", "", facts.InventoryCreate{Host: pattern})
	require.Equal(t, 201, active.Code)
	require.Equal(t, "active", decode(active).Status)
	require.Equal(t, 400, call("POST", "/inventory/records", "admin", "", facts.InventoryCreate{Host: host}).Code)
	require.Equal(t, 405, call("OPTIONS", "/inventory/records", "admin", "", nil).Code)
	require.Equal(t, 404, call("POST", "/manage", "admin", "", nil).Code)
	// Omitting accounts is rejected before any backend mutation.
	invalid := map[string]any{"host": map[string]any{"name": []string{"bad"}, "principal": map[string]string{"mode": "account-name"}}}
	require.Equal(t, 400, call("POST", "/inventory/records", "", "", invalid).Code)
	require.Equal(t, http.StatusOK, call("GET", "/inventory/audit", "admin", "", nil).Code)
}
