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
	require.Len(t, options.Header().Values("Link-Template"), 2)
	host := &facts.InventoryHost{Name: []string{"one.example"}, Accounts: []string{}, Principal: facts.InventoryPrincipal{Mode: "account-name"}}
	created := call("POST", "/inventory/records/"+inventory.NewID(), "provisioner", "", facts.InventoryCreate{Host: host})
	require.Equal(t, 200, created.Code, created.Body.String())
	h := decode(created)
	require.Equal(t, "active", h.Status)
	require.Equal(t, `"1"`, created.Header().Get("ETag"))
	require.NotContains(t, created.Body.String(), `"revision"`)
	path := created.Header().Get("Location")
	require.Equal(t, 403, call("GET", path, "", "", nil).Code)
	require.Equal(t, 428, call("PUT", path, "admin", "", h).Code)
	// Lifecycle changes are no longer supported, even for administrators.
	h.Status = "pending"
	require.Equal(t, 400, call("PUT", path, "admin", `"1"`, h).Code)
	h.Status = "active"
	h.Host.Attributes = map[string]string{"environment": "prod"}
	updated := call("PUT", path, "admin", `"1"`, h)
	require.Equal(t, 200, updated.Code, updated.Body.String())
	require.Equal(t, `"2"`, updated.Header().Get("ETag"))
	require.Equal(t, 412, call("PUT", path, "admin", `"1"`, h).Code)
	h = decode(updated)
	h.CreatedAt = h.CreatedAt.Add(1)
	require.Equal(t, 400, call("PUT", path, "admin", `"2"`, h).Code)
	h = decode(updated)
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
	// Inventory no longer exposes credential creation or revocation.
	for _, method := range []string{"GET", "POST", "DELETE"} {
		require.Equal(t, 404, call(method, "/inventory/tokens", "admin", "", nil).Code)
	}
	id := inventory.NewID()
	admitted := call("POST", "/inventory/records/"+id, "provisioner", "", facts.InventoryCreate{Host: host})
	require.Equal(t, 200, admitted.Code, admitted.Body.String())
	require.Equal(t, 200, call("POST", "/inventory/records/"+id, "provisioner", "", facts.InventoryCreate{Host: host}).Code)
	changed := *host
	changed.Accounts = []string{"root"}
	require.Equal(t, 409, call("POST", "/inventory/records/"+id, "provisioner", "", facts.InventoryCreate{Host: &changed}).Code)
	// The old actorless and token-in-body creation paths are rejected.
	require.Equal(t, 403, call("POST", "/inventory/records/"+inventory.NewID(), "", "", facts.InventoryCreate{Host: host}).Code)
	require.Equal(t, 400, call("POST", "/inventory/records/"+inventory.NewID(), "provisioner", "", map[string]any{"host": host, "token": "old"}).Code)
	pattern := &facts.InventoryHost{Name: []string{"*.example"}, Accounts: nil, Principal: facts.InventoryPrincipal{Mode: "account-name"}}
	active := call("POST", "/inventory/records/"+inventory.NewID(), "admin", "", facts.InventoryCreate{Host: pattern})
	require.Equal(t, 200, active.Code)
	require.Equal(t, "active", decode(active).Status)
	edited := decode(active)
	edited.Host.Attributes = map[string]string{"environment": "prod"}
	require.Equal(t, 200, call("PUT", active.Header().Get("Location"), "admin", active.Header().Get("ETag"), edited).Code)

	require.Equal(t, 405, call("OPTIONS", "/inventory/records", "admin", "", nil).Code)
	require.Equal(t, 404, call("POST", "/manage", "admin", "", nil).Code)
	// Omitting accounts is rejected before any backend mutation.
	invalid := map[string]any{"host": map[string]any{"name": []string{"bad"}, "principal": map[string]string{"mode": "account-name"}}}
	require.Equal(t, 400, call("POST", "/inventory/records/"+inventory.NewID(), "provisioner", "", invalid).Code)
	audit := call("GET", "/inventory/audit", "admin", "", nil)
	require.Equal(t, http.StatusOK, audit.Code)
	var page facts.AuditPage[facts.HostAuditEvent]
	require.NoError(t, json.Unmarshal(audit.Body.Bytes(), &page))
	events := page.Events
	expected := []struct{ action, actor, resource string }{
		{"create", "provisioner", decode(created).ID},
		{"edit", "admin", decode(created).ID},
		{"remove", "admin", decode(created).ID},
		{"create", "provisioner", decode(admitted).ID},
		{"create", "admin", decode(active).ID},
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
	require.Equal(t, decode(updated).UpdatedAt, events[1].At)
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
	var allIDs []string
	for i := 1; i <= 6; i++ {
		id := fmt.Sprintf("%064x", i)
		allIDs = append(allIDs, id)
		if i%2 == 0 {
			_, err = store.UpsertHost(t.Context(), inventory.Host{ID: id, Status: inventory.StatusActive, Names: []string{fmt.Sprintf("*.%d.example", i)}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}, inventory.WriteConditions{}, inventory.NewAuditEvent("admin", "add", id))
		} else {
			_, err = inventory.CreateHost(t.Context(), store, id, inventory.Host{Names: []string{fmt.Sprintf("host-%d.example", i)}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}, inventory.NewAuditEvent("host", "enroll", id))
		}
		require.NoError(t, err)
	}
	{
		var actual []string
		after := ""
		for pageNumber := 0; pageNumber < 5; pageNumber++ {
			req := httptest.NewRequest("GET", fmt.Sprintf("http://inventory/inventory/records?limit=2&after=%s", after), nil)
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
		require.Equal(t, allIDs, actual)
	}
}
