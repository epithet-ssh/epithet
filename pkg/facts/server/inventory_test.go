package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
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
	created := call("PUT", "/inventory/records/"+inventory.NewID(), "", "", facts.InventoryCreate{Host: host})
	require.Equal(t, 200, created.Code, created.Body.String())
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
	require.Equal(t, 404, reserved.Code)
	admitted := call("PUT", "/inventory/records/"+token.Token, "", "", facts.InventoryCreate{Host: host, Token: token.Token})
	require.Equal(t, 200, admitted.Code, admitted.Body.String())
	require.Equal(t, token.Token, decode(admitted).ID)
	require.Equal(t, 200, call("PUT", "/inventory/records/"+token.Token, "", "", facts.InventoryCreate{Host: host, Token: token.Token}).Code)
	require.Equal(t, 204, call("DELETE", "/inventory/tokens?token="+token.Token, "admin", "", nil).Code)
	// Administrator review applies to an actual pending host.
	pending := call("PUT", "/inventory/records/"+inventory.NewID(), "", "", facts.InventoryCreate{Host: host})
	h = decode(pending)
	h.Status = "denied"
	denied := call("PUT", pending.Header().Get("Location"), "admin", pending.Header().Get("ETag"), h)
	require.Equal(t, 200, denied.Code, denied.Body.String())
	require.NotNil(t, decode(denied).Host)
	// Enrollment requires exact names; administrators may create wildcard names.
	pattern := &facts.InventoryHost{Name: []string{"*.example"}, Accounts: nil, Principal: facts.InventoryPrincipal{Mode: "account-name"}}
	rejected := call("PUT", "/inventory/records/"+inventory.NewID(), "", "", facts.InventoryCreate{Host: pattern})
	require.Equal(t, 400, rejected.Code, rejected.Body.String())
	active := call("POST", "/inventory/records", "admin", "", facts.InventoryCreate{Host: pattern})
	require.Equal(t, 201, active.Code)
	require.Equal(t, "active", decode(active).Status)
	edited := decode(active)
	edited.Host.Attributes = map[string]string{"environment": "prod"}
	require.Equal(t, 200, call("PUT", active.Header().Get("Location"), "admin", active.Header().Get("ETag"), edited).Code)

	require.Equal(t, 405, call("OPTIONS", "/inventory/records", "admin", "", nil).Code)
	require.Equal(t, 404, call("POST", "/manage", "admin", "", nil).Code)
	// Omitting accounts is rejected before any backend mutation.
	invalid := map[string]any{"host": map[string]any{"name": []string{"bad"}, "principal": map[string]string{"mode": "account-name"}}}
	require.Equal(t, 400, call("PUT", "/inventory/records/"+inventory.NewID(), "", "", invalid).Code)
	audit := call("GET", "/inventory/audit", "admin", "", nil)
	require.Equal(t, http.StatusOK, audit.Code)
	var page facts.AuditPage[facts.HostAuditEvent]
	require.NoError(t, json.Unmarshal(audit.Body.Bytes(), &page))
	events := page.Events
	expected := []struct{ action, actor, resource string }{
		{"enroll", "host", decode(created).ID},
		{"approve", "admin", decode(created).ID},
		{"remove", "admin", decode(created).ID},
		{"token-create", "admin", decode(admitted).ID},
		{"enroll", "host", decode(admitted).ID},
		{"token-revoke", "admin", decode(admitted).ID},
		{"enroll", "host", decode(denied).ID},
		{"deny", "admin", decode(denied).ID},
		{"add", "admin", decode(active).ID},
		{"edit", "admin", decode(active).ID},
	}
	require.Len(t, events, len(expected))
	for i, want := range expected {
		require.Equal(t, want.action, events[i].Action)
		require.Equal(t, want.actor, events[i].Actor)
		require.Equal(t, want.resource, events[i].Resource)
		require.False(t, events[i].At.IsZero())
	}
	require.Equal(t, decode(created).CreatedAt, events[0].At)
	require.Equal(t, decode(approved).UpdatedAt, events[1].At)
}

func TestInventoryListIncludesWildcardNames(t *testing.T) {
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	store, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	handler, err := factserver.InventoryHandler(store, "", pub, factserver.WithInventoryManagement(store))
	require.NoError(t, err)
	signer, err := serviceauth.NewSignerFor(key, serviceauth.InventoryAudience)
	require.NoError(t, err)
	var allIDs, hostIDs []string
	for i := 1; i <= 6; i++ {
		id := fmt.Sprintf("%064x", i)
		allIDs = append(allIDs, id)
		if i%2 == 0 {
			_, err = store.CreateHost(t.Context(), id, inventory.Host{Status: inventory.StatusActive, Names: []string{fmt.Sprintf("*.%d.example", i)}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}, inventory.NewAuditEvent("admin", "add", id))
		} else {
			_, err = inventory.Enroll(t.Context(), store, id, inventory.Host{Names: []string{fmt.Sprintf("host-%d.example", i)}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}, "", inventory.NewAuditEvent("host", "enroll", id))
			hostIDs = append(hostIDs, id)
		}
		require.NoError(t, err)
	}
	for _, pending := range []bool{false, true} {
		var actual []string
		after := ""
		for pageNumber := 0; pageNumber < 5; pageNumber++ {
			req := httptest.NewRequest("GET", fmt.Sprintf("http://inventory/inventory/records?limit=2&after=%s&pending=%t", after, pending), nil)
			require.NoError(t, signer.AuthorizeActor(req, nil, "admin"))
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, req)
			require.Equal(t, 200, out.Code, out.Body.String())
			var page []facts.InventoryRecord
			require.NoError(t, json.Unmarshal(out.Body.Bytes(), &page))
			require.LessOrEqual(t, len(page), 2)
			if len(page) == 0 {
				break
			}
			for _, record := range page {
				actual = append(actual, record.ID)
			}
			after = page[len(page)-1].ID
		}
		if pending {
			require.Equal(t, hostIDs, actual)
		} else {
			require.Equal(t, allIDs, actual)
		}
	}
}
