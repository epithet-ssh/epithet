package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestSCIMDiscoveredTransportAndResourceReferences(t *testing.T) {
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(pub, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	const query = `filter=userName%20eq%20%22a%2Bb%22&attributes=id&attributes=meta`
	const input = `{"userName":"alice","custom":9007199254740993}`
	var origin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		actor, err := verifier.VerifyActor(r, body)
		require.NoError(t, err)
		if r.URL.Path == "/tenant/facts" {
			require.Empty(t, actor)
			if r.Method == "GET" {
				require.Equal(t, "alice", r.URL.Query().Get("id"))
				fmt.Fprint(w, `{"id":"alice"}`)
				return
			}
			require.Equal(t, "OPTIONS", r.Method)
			w.Header().Set("Link", `<unrelated>; rel="other"; title="one,two", <../directory/scim>; rel="alternate `+wire.RelSCIM+`"`)
			w.WriteHeader(204)
			return
		}
		require.Equal(t, "admin", actor)
		require.Equal(t, "/directory/scim/Users/a%2Fb", r.URL.EscapedPath())
		require.Equal(t, "PUT", r.Method)
		require.Equal(t, query, r.URL.RawQuery)
		require.Equal(t, input, string(body))
		require.Equal(t, `W/"3"`, r.Header.Get("If-Match"))
		require.Equal(t, "application/scim+json", r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/scim+json")
		w.Header().Set("ETag", `W/"4"`)
		w.Header().Set("Location", origin+"/directory/scim/Users/a%2Fb")
		fmt.Fprintf(w, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"meta":{"location":%q},"groups":[{"$ref":"/directory/scim/Groups/g"}],"urn:example:extension":{"meta":{"location":"/directory/scim/Users/private"},"number":9007199254740993}},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"members":[{"$ref":"/directory/scim/Users/a%%2Fb"},{"$ref":"https://outside.example/Users/elsewhere"}]}]}`, origin+"/directory/scim/Users/a%2Fb")
	}))
	defer server.Close()
	origin = server.URL
	cfg := tlsconfig.Config{Insecure: true}
	client, err := newSCIMTestServer(server.URL+"/tenant/facts", key, cfg)
	require.NoError(t, err)
	result, err := client.provision(t.Context(), servicehttp.Request{Actor: "admin", Method: "PUT", URL: "/scim/v2/Users/a%2Fb?" + query, ContentType: "application/scim+json", IfMatch: `W/"3"`, Body: []byte(input)})
	require.NoError(t, err)
	require.Equal(t, 200, result.Status)
	require.Equal(t, `W/"4"`, result.Header.Get("ETag"))
	require.Equal(t, "/scim/v2/Users/a%2Fb", result.Header.Get("Location"))
	var doc struct{ Resources []json.RawMessage }
	require.NoError(t, json.Unmarshal(result.Body, &doc))
	require.Contains(t, string(doc.Resources[0]), `"location":"/scim/v2/Users/a%2Fb"`)
	require.Contains(t, string(doc.Resources[0]), `"$ref":"/scim/v2/Groups/g"`)
	require.Contains(t, string(doc.Resources[0]), `"location":"/directory/scim/Users/private"`)
	require.Contains(t, string(doc.Resources[0]), `9007199254740993`)
	require.Contains(t, string(doc.Resources[1]), `"$ref":"/scim/v2/Users/a%2Fb"`)
	require.Contains(t, string(doc.Resources[1]), `https://outside.example/Users/elsewhere`)
	data, err := facts.NewDataClient(server.URL+"/tenant/facts", "", key, cfg)
	require.NoError(t, err)
	user, err := data.User(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", user.ID)
}

func TestSCIMDiscoveryFallbackAndFailures(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	for _, status := range []int{200, 204, 400, 401, 403, 404, 405, 429, 301, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/facts", r.URL.Path)
				if r.Method == "GET" {
					fmt.Fprint(w, `{"id":"alice"}`)
					return
				}
				require.Equal(t, "OPTIONS", r.Method)
				w.WriteHeader(status)
			}))
			defer server.Close()
			cfg := tlsconfig.Config{Insecure: true}
			client, err := newSCIMTestServer(server.URL+"/facts", key, cfg)
			require.NoError(t, err)
			_, err = client.provision(t.Context(), servicehttp.Request{Actor: "admin", Method: "GET", URL: "/scim/v2/Users"})
			if status < 300 || status >= 400 && status < 500 {
				require.ErrorIs(t, err, facts.ErrNotFound)
			} else {
				require.ErrorIs(t, err, facts.ErrUnavailable)
			}
			data, err := facts.NewDataClient(server.URL+"/facts", "", key, cfg)
			require.NoError(t, err)
			user, err := data.User(t.Context(), "alice")
			require.NoError(t, err)
			require.NotNil(t, user)
		})
	}
	for _, target := range []string{"https://user:pass@example.com/scim/", "/scim/?tenant=x", "/scim/#fragment", "ftp://example.com/scim/", "/%zz"} {
		t.Run(target, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "OPTIONS", r.Method)
				w.Header().Set("Link", "<"+target+">; rel=\""+wire.RelSCIM+"\"")
				w.WriteHeader(204)
			}))
			defer server.Close()
			client, err := newSCIMTestServer(server.URL, key, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			_, err = client.provision(t.Context(), servicehttp.Request{Actor: "admin", Method: "GET", URL: "/scim/v2/Users"})
			require.Error(t, err)
		})
	}
}

func TestSCIMOperationRejectionsAndRedirects(t *testing.T) {
	_, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	for _, status := range []int{403, 404, 412, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "OPTIONS" {
					w.Header().Set("Link", `</scim/>; rel="`+wire.RelSCIM+`"`)
					w.WriteHeader(204)
					return
				}
				require.Equal(t, "/scim/Users/u", r.URL.Path)
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"detail":"provider rejected"}`)
			}))
			defer server.Close()
			client, err := newSCIMTestServer(server.URL+"/facts", key, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			result, err := client.provision(t.Context(), servicehttp.Request{Actor: "admin", Method: "DELETE", URL: "/scim/v2/Users/u"})
			if status == 302 {
				require.ErrorIs(t, err, facts.ErrUnavailable)
			} else {
				require.NoError(t, err)
				require.Equal(t, status, result.Status)
				require.Contains(t, string(result.Body), "provider rejected")
			}
			for _, path := range []string{"/scim/v2/../manage", "/scim/v2/Users/%2e%2e/../actor", "https://example.com/scim/v2/Users", "/manage"} {
				_, err = client.provision(t.Context(), servicehttp.Request{Actor: "admin", Method: "GET", URL: path})
				require.ErrorIs(t, err, facts.ErrInvalid)
			}
		})
	}
}

func TestSCIMUnixDiscovery(t *testing.T) {
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(pub, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	dir, err := os.MkdirTemp("/tmp", "scim-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "d.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, err := verifier.VerifyActor(r, nil)
		require.NoError(t, err)
		if r.Method == "OPTIONS" {
			require.Equal(t, "/lookup", r.URL.Path)
			require.Empty(t, actor)
			w.Header().Set("Link", `</scim/>; rel="`+wire.RelSCIM+`"`)
			w.WriteHeader(204)
			return
		}
		require.Equal(t, "admin", actor)
		require.Equal(t, "/scim/Users", r.URL.Path)
		fmt.Fprint(w, `{"Resources":[]}`)
	})}
	go server.Serve(listener)
	defer server.Close()
	client, err := newSCIMTestServer("unix://"+socket, key, tlsconfig.Config{})
	require.NoError(t, err)
	result, err := client.provision(t.Context(), servicehttp.Request{Actor: "admin", Method: "GET", URL: "/scim/v2/Users"})
	require.NoError(t, err)
	require.Equal(t, 200, result.Status)
	require.True(t, strings.Contains(string(result.Body), "Resources"))
}

// Build only the private forwarding dependency; public authentication has its
// own handler tests in scim_test.go.
func newSCIMTestServer(endpoint string, key sshcert.RawPrivateKey, cfg tlsconfig.Config) (*Server, error) {
	client, err := servicehttp.New(endpoint, "/lookup", key, serviceauth.DirectoryAudience, cfg)
	if err != nil {
		return nil, err
	}
	return &Server{directory: client}, nil
}
func TestSCIMProvisioningMetadata(t *testing.T) {
	public, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	verifier, err := serviceauth.NewVerifierFor(public, serviceauth.DirectoryAudience)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		actor, err := verifier.VerifyActor(r, body)
		require.NoError(t, err)
		require.Empty(t, actor)
		switch r.URL.Path {
		case "/lookup":
			require.Equal(t, "OPTIONS", r.Method)
			w.Header().Set("Link", `</scim/v2/>; rel="`+wire.RelSCIM+`"`)
			w.WriteHeader(204)
		case "/scim/v2/Users/id":
			require.Equal(t, "DELETE", r.Method)
			require.Equal(t, "attributes=id", r.URL.RawQuery)
			require.Equal(t, `W/"3"`, r.Header.Get("If-Match"))
			require.Equal(t, "application/scim+json", r.Header.Get("Content-Type"))
			w.Header().Set("Content-Type", "application/scim+json")
			w.Header().Set("ETag", `W/"4"`)
			w.Header().Set("Location", "/scim/v2/Users/id")
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			w.Header().Set("Authorization", "must-not-escape")
			w.WriteHeader(412)
			fmt.Fprint(w, `{"status":"412","detail":"stale revision"}`)
		}
	}))
	defer server.Close()
	provision, err := newSCIMTestServer(server.URL+"/lookup", key, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	result, err := provision.provision(t.Context(), servicehttp.Request{Actor: "", Method: "DELETE", URL: "/scim/v2/Users/id?attributes=id", ContentType: "application/scim+json", IfMatch: `W/"3"`})
	require.NoError(t, err)
	require.Equal(t, 412, result.Status)
	require.Equal(t, `W/"4"`, result.Header.Get("ETag"))
	require.Equal(t, "/scim/v2/Users/id", result.Header.Get("Location"))
	require.Equal(t, "application/scim+json", result.Header.Get("Content-Type"))
	require.Equal(t, `Bearer realm="scim"`, result.Header.Get("WWW-Authenticate"))
	require.JSONEq(t, `{"status":"412","detail":"stale revision"}`, string(result.Body))
}
