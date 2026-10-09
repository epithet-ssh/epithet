package factservice_test

import (
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

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/factservice"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

type users struct{ active bool }

func (u *users) LookupUser(_ context.Context, id string) (*directory.User, directory.Revision, error) {
	if id == "missing" {
		return nil, "", nil
	}
	return &directory.User{ID: id, Active: u.active}, "opaque-revision", nil
}
func TestDirectoryLookupContract(t *testing.T) {
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	source := &users{active: true}
	handler, err := factservice.Handler(source, nil, pub, "")
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := factservice.NewClient(server.URL, key, serviceauth.DirectoryAudience, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	id := "opaque+id & slash/ ? こんにちは"
	u, err := client.User(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, id, u.ID)
	require.Empty(t, u.UserName)
	require.Empty(t, u.Groups)
	require.Equal(t, "opaque-revision", u.Revision.String())
	source.active = false
	u, err = client.User(t.Context(), id)
	require.NoError(t, err)
	require.Nil(t, u, "same lookup must not reuse active facts")
	signed, err := serviceauth.NewClient(server.URL, key, serviceauth.DirectoryAudience, tlsconfig.Config{Insecure: true})
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
	wrong, err := serviceauth.NewClient(server.URL, key, serviceauth.InventoryAudience, tlsconfig.Config{Insecure: true})
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
		{"optional fields", `{"id":"id","userName":"alice","groups":["ops"],"department":"eng"}`, false, true},
		{"opaque revision", `{"id":"id","revision":"not a hash"}`, false, true},
		{"max revision", `{"id":"id","revision":"` + strings.Repeat("x", 256) + `"}`, false, true},
		{"oversize revision", `{"id":"id","revision":"` + strings.Repeat("é", 129) + `"}`, false, false},
		{"null revision", `{"id":"id","revision":null}`, false, false},
		{"numeric revision", `{"id":"id","revision":1}`, false, false},
		{"missing id", `{}`, false, false}, {"mismatch", `{"id":"other"}`, false, false}, {"null user", `null`, false, false},
		{"unrestricted", `{"names":["host","alias"],"accounts":null,"principal":{"mode":"account-name"}}`, true, true},
		{"no accounts", `{"names":["host"],"accounts":[],"principal":{"mode":"account-name"}}`, true, true},
		{"opaque realm", `{"names":["host"],"accounts":["root"],"principal":{"mode":"epithet-principal-v1","realm":"fleet"},"revision":"inventory-v1"}`, true, true},
		{"missing accounts", `{"names":["host"],"principal":{"mode":"account-name"}}`, true, false},
		{"missing principal", `{"names":["host"],"accounts":null}`, true, false},
		{"no realm", `{"names":["host"],"accounts":null,"principal":{"mode":"epithet-principal-v1"}}`, true, false},
		{"wrong names", `{"names":["other"],"accounts":null,"principal":{"mode":"account-name"}}`, true, false},
		{"host revision null", `{"names":["host"],"accounts":null,"principal":{"mode":"account-name"},"revision":null}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Equal(t, "no-store", r.Header.Get("Cache-Control"))
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			client, err := factservice.NewClient(server.URL, key, serviceauth.DirectoryAudience, tlsconfig.Config{Insecure: true})
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
			client, err := factservice.NewClient(server.URL, key, serviceauth.DirectoryAudience, tlsconfig.Config{Insecure: true})
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
	handler, err := factservice.Handler(&users{active: true}, nil, pub, "")
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
	client, err := factservice.NewClient("unix://"+path, key, serviceauth.DirectoryAudience, tlsconfig.Config{})
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
	_, err = factservice.Handler(&users{active: true}, nil, pub, pub)
	require.ErrorContains(t, err, "distinct signing keys")
}

func TestRevisionPreservesPresenceAndUTF8Bound(t *testing.T) {
	for _, kind := range []string{"user", "host"} {
		for _, revision := range []string{"", `,"revision":""`, `,"revision":"opaque"`} {
			t.Run(kind+revision, func(t *testing.T) {
				var value any
				data := `{"id":"id"` + revision + `}`
				if kind == "user" {
					value = &factservice.User{}
				} else {
					value = &factservice.Host{}
					data = `{"names":["host"],"accounts":null,"principal":{"mode":"account-name"}` + revision + `}`
				}
				require.NoError(t, json.Unmarshal([]byte(data), value))
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
	}
	var r factservice.Revision
	require.Error(t, json.Unmarshal([]byte{'"', 0xff, '"'}, &r))
}

func TestManagedPatternConflictIsReportedAcrossFactTransport(t *testing.T) {
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	hosts, err := inventory.OpenManaged(filepath.Join(t.TempDir(), "inventory.db"))
	require.NoError(t, err)
	defer hosts.Close()
	for _, pattern := range []string{"*.example", "ci-*.*"} {
		_, err = hosts.AddPattern("admin", inventory.Proposal{Pattern: pattern, Accounts: []string{"root"}, PrincipalMode: inventory.AccountNamePrincipals})
		require.NoError(t, err)
	}
	handler, err := factservice.Handler(nil, hosts, pub, "")
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	defer server.Close()
	signed, err := serviceauth.NewClient(server.URL, key, serviceauth.InventoryAudience, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	resp, err := signed.Do(t.Context(), "GET", "/lookup", url.Values{"host": {"ci-one.example"}}, nil, "")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	client, err := factservice.NewClient(server.URL, key, serviceauth.InventoryAudience, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	h, err := client.Host(t.Context(), "ci-one.example")
	require.Nil(t, h)
	require.ErrorContains(t, err, "inventory conflict")
	require.ErrorContains(t, err, "ci-one.example matches pattern records")
	require.NoError(t, hosts.Close())
	_, err = client.Host(t.Context(), "ci-one.example")
	require.ErrorContains(t, err, "HTTP 503")
}
