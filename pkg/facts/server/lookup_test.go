package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	inventorysqlite "github.com/epithet-ssh/epithet/pkg/facts/inventory/sqlitestore"
	factserver "github.com/epithet-ssh/epithet/pkg/facts/server"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

type users struct{ active bool }

func (u *users) LookupUser(_ context.Context, id string) (*directory.User, error) {
	if id == "missing" {
		return nil, nil
	}
	return &directory.User{ID: id, Active: u.active}, nil
}
func TestDirectoryLookupContract(t *testing.T) {
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	source := &users{active: true}
	handler, err := factserver.DirectoryHandler(source, pub, "")
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := facts.NewDataClient(server.URL+"/lookup", "", key, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	id := "opaque+id & slash/ ? こんにちは"
	u, err := client.User(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, id, u.ID)
	require.Empty(t, u.UserName)
	require.Empty(t, u.Groups)
	require.True(t, u.Revision.IsZero())
	source.active = false
	u, err = client.User(t.Context(), id)
	require.NoError(t, err)
	require.Nil(t, u, "same lookup must not reuse active facts")
	signed, err := newSignedTestClient(server.URL, key, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	for _, id := range []string{"missing", "inactive"} {
		resp, err := signed.Do(t.Context(), "GET", "/lookup", url.Values{"id": {id}}, nil, "")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, 404, resp.StatusCode)
		require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	}
	for _, q := range []url.Values{{}, {"id": {"one", "two"}}, {"id": {"one"}, "extra": {"x"}}, {"host": {"one"}}} {
		resp, err := signed.Do(t.Context(), "GET", "/lookup", q, nil, "")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, 400, resp.StatusCode)
	}
	resp, err := signed.Do(t.Context(), "GET", "/lookup", url.Values{"id": {"one"}}, []byte("x"), "")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 400, resp.StatusCode)
	wrong, err := newSignedTestClient(server.URL, key, serviceauth.InventoryAudience)
	require.NoError(t, err)
	resp, err = wrong.Do(t.Context(), "GET", "/lookup", url.Values{"id": {"one"}}, nil, "")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 403, resp.StatusCode)
}

func TestBespokeProviderResponseValidation(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	for _, tc := range []struct {
		name, body  string
		host, valid bool
	}{
		{"minimal user", `{"id":"id"}`, false, true},
		{"optional fields", `{"id":"id","userName":"alice","name":["alice"],"groups":[{"name":["ops"]}],"attributes":{"department":"eng"}}`, false, true},
		{"numeric user attribute", `{"id":"id","attributes":{"cost":1}}`, false, false},
		{"null group member", `{"id":"id","groups":[null]}`, false, false},
		{"null name member", `{"id":"id","name":[null]}`, false, false},
		{"null attribute member", `{"id":"id","attributes":{"role":["ops",null]}}`, false, false},
		{"shadow name", `{"id":"id","attributes":{"name":"forged"}}`, false, false},
		{"shadow group id", `{"id":"id","groups":[{"attributes":{"id":"forged"}}]}`, false, false},
		{"host attribute type", `{"name":["host"],"accounts":null,"attributes":{"cost":false},"principal":{"mode":"account-name"}}`, true, false},
		{"null account member", `{"name":["host"],"accounts":[null],"principal":{"mode":"account-name"}}`, true, false},
		{"opaque revision", `{"id":"id","revision":"not a hash"}`, false, true},
		{"max revision", `{"id":"id","revision":"` + strings.Repeat("x", 256) + `"}`, false, true},
		{"oversize revision", `{"id":"id","revision":"` + strings.Repeat("é", 129) + `"}`, false, false},
		{"null revision", `{"id":"id","revision":null}`, false, false},
		{"numeric revision", `{"id":"id","revision":1}`, false, false},
		{"missing id", `{}`, false, false}, {"mismatch", `{"id":"other"}`, false, false}, {"null user", `null`, false, false},
		{"unrestricted", `{"name":["host","alias"],"accounts":null,"principal":{"mode":"account-name"}}`, true, true},
		{"no accounts", `{"name":["host"],"accounts":[],"principal":{"mode":"account-name"}}`, true, true},
		{"opaque realm", `{"name":["host"],"accounts":["root"],"principal":{"mode":"epithet-principal-v1","realm":"fleet"},"revision":"inventory-v1"}`, true, true},
		{"missing accounts", `{"name":["host"],"principal":{"mode":"account-name"}}`, true, false},
		{"missing principal", `{"name":["host"],"accounts":null}`, true, false},
		{"no realm", `{"name":["host"],"accounts":null,"principal":{"mode":"epithet-principal-v1"}}`, true, false},
		{"wrong names", `{"name":["other"],"accounts":null,"principal":{"mode":"account-name"}}`, true, false},
		{"ignored host revision", `{"name":["host"],"accounts":null,"principal":{"mode":"account-name"},"revision":null}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Equal(t, "no-store", r.Header.Get("Cache-Control"))
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			directoryURL, inventoryURL := server.URL, ""
			if tc.host {
				directoryURL, inventoryURL = "", server.URL+"/lookup"
			}
			client, err := facts.NewDataClient(directoryURL, inventoryURL, key, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			if tc.host {
				_, err = client.Host(t.Context(), "host")
			} else {
				_, err = client.User(t.Context(), "id")
			}
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestProviderStatusAndNoRedirects(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed fact redirect") }))
	defer dest.Close()
	for _, status := range []int{200, 301, 401, 403, 404, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", dest.URL)
				w.WriteHeader(status)
				io.WriteString(w, `{"id":"id"}`)
			}))
			defer server.Close()
			client, err := facts.NewDataClient(server.URL+"/lookup", "", key, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			u, err := client.User(t.Context(), "id")
			if status == 200 {
				require.NoError(t, err)
				require.NotNil(t, u)
			} else if status == 404 {
				require.NoError(t, err)
				require.Nil(t, u)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestUnixFactTransport(t *testing.T) {
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	handler, err := factserver.DirectoryHandler(&users{active: true}, pub, "")
	require.NoError(t, err)
	// A short directory is required for the macOS Unix socket path limit.
	dir := t.TempDir()
	path := filepath.Join(dir, "f.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("socket path unavailable: %v", err)
	}
	server := &http.Server{Handler: handler}
	defer server.Close()
	go server.Serve(listener)
	client, err := facts.NewDataClient("unix://"+path, "", key, tlsconfig.Config{})
	require.NoError(t, err)
	user, err := client.User(t.Context(), "id")
	require.NoError(t, err)
	require.Equal(t, "id", user.ID)
	data, err := json.Marshal(user)
	require.NoError(t, err)
	require.NotContains(t, string(data), "active")
}

func TestFactReaderAndControlKeysMustDiffer(t *testing.T) {
	pub, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	_, err = factserver.DirectoryHandler(&users{active: true}, pub, pub)
	require.ErrorContains(t, err, "distinct signing keys")
}

func TestRevisionPreservesPresenceAndUTF8Bound(t *testing.T) {
	for _, revision := range []string{"", `,"revision":""`, `,"revision":"opaque"`} {
		t.Run(revision, func(t *testing.T) {
			var value facts.User
			require.NoError(t, json.Unmarshal([]byte(`{"id":"id"`+revision+`}`), &value))
			encoded, err := json.Marshal(value)
			require.NoError(t, err)
			var fields map[string]any
			require.NoError(t, json.Unmarshal(encoded, &fields))
			if revision == "" {
				require.NotContains(t, fields, "revision")
			} else {
				require.Contains(t, fields, "revision")
			}
		})
	}
	var r facts.Revision
	require.Error(t, json.Unmarshal([]byte{'"', 0xff, '"'}, &r))
}

func TestManagedPatternConflictIsReportedAcrossFactTransport(t *testing.T) {
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	hosts, err := inventorysqlite.Open(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer hosts.Close()
	for _, pattern := range []string{"*.example", "ci-*.*"} {
		id1 := inventory.NewID()
		_, err = hosts.AddHost(t.Context(), id1, inventory.Host{Names: []string{pattern}, Accounts: []string{"root"}, PrincipalMode: inventory.AccountNamePrincipals}, inventory.NewAuditEvent("admin", "add", id1))
		require.NoError(t, err)
	}
	handler, err := factserver.InventoryHandler(hosts, pub, "")
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	defer server.Close()
	signed, err := newSignedTestClient(server.URL, key, serviceauth.InventoryAudience)
	require.NoError(t, err)
	resp, err := signed.Do(t.Context(), "GET", "/lookup", url.Values{"host": {"ci-one.example"}}, nil, "")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	client, err := facts.NewDataClient("", server.URL+"/lookup", key, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	h, err := client.Host(t.Context(), "ci-one.example")
	require.Nil(t, h)
	require.ErrorContains(t, err, "inventory conflict")
	require.ErrorContains(t, err, "ci-one.example matches wildcard names on hosts")
	require.NoError(t, hosts.Close())
	_, err = client.Host(t.Context(), "ci-one.example")
	require.ErrorContains(t, err, "HTTP 503")
}

// signedTestClient sends malformed and cross-audience requests at the protocol
// boundary. Raw HTTP stays test-only; production clients expose domain methods.
type signedTestClient struct {
	endpoint string
	signer   *serviceauth.Signer
}

func newSignedTestClient(endpoint string, key sshcert.RawPrivateKey, audience string) (*signedTestClient, error) {
	signer, err := serviceauth.NewSignerFor(key, audience)
	if err != nil {
		return nil, err
	}
	return &signedTestClient{endpoint: endpoint, signer: signer}, nil
}
func (c *signedTestClient) Do(ctx context.Context, method, path string, query url.Values, body []byte, actor string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = query.Encode()
	if err = c.signer.AuthorizeActor(req, body, actor); err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}
