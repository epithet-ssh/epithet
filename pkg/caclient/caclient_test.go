package caclient_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StubExample(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
	defer server.Close()

	client := server.Client()
	res, err := client.Post(server.URL, "application/json", bytes.NewBufferString(`{
		"pubkey":"hello",
		"token":"world"
	}`))
	require.NoError(err)

	body, err := ioutil.ReadAll(res.Body)
	require.NoError(err)

	assert.Equal("hello world", string(body))
}

func TestClient_StatusCodes(t *testing.T) {
	// Test 4xx status codes that don't trip circuit breaker
	// Note: 5xx responses trip the circuit breaker, which changes the error type,
	// so we test them separately in integration tests
	tests := []struct {
		name       string
		statusCode int
		checkErr   func(t *testing.T, err error)
	}{
		{
			"401 returns InvalidTokenError",
			http.StatusUnauthorized,
			func(t *testing.T, err error) {
				var e *caclient.InvalidTokenError
				assert.True(t, errors.As(err, &e), "expected InvalidTokenError, got %T", err)
			},
		},
		{
			"403 returns PolicyDeniedError",
			http.StatusForbidden,
			func(t *testing.T, err error) {
				var e *caclient.PolicyDeniedError
				assert.True(t, errors.As(err, &e), "expected PolicyDeniedError, got %T", err)
			},
		},
		{
			"400 returns InvalidRequestError",
			http.StatusBadRequest,
			func(t *testing.T, err error) {
				var e *caclient.InvalidRequestError
				assert.True(t, errors.As(err, &e), "expected InvalidRequestError, got %T", err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("test error message"))
			}))
			defer server.Close()

			endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
			client, err := caclient.New(endpoints)
			require.NoError(t, err)

			pubKey := sshcert.RawPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB")
			conn := policy.Connection{
				RemoteHost: "server.example.com",
				RemoteUser: "user",
				Port:       22,
			}
			_, err = client.GetCert(context.Background(), "test-token", &caserver.CreateCertRequest{
				PublicKey:  pubKey,
				Connection: conn,
			})

			require.Error(t, err)
			tt.checkErr(t, err)
		})
	}
}

func TestGetCert_ReturnsCertificate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA..."}`))
	}))
	defer server.Close()

	endpoints := []caclient.CAEndpoint{{URL: server.URL, Priority: caclient.DefaultPriority}}
	client, err := caclient.New(endpoints)
	require.NoError(t, err)

	pubKey := sshcert.RawPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB")
	conn := policy.Connection{
		RemoteHost: "server.example.com",
		RemoteUser: "alice",
		Port:       22,
	}
	resp, err := client.GetCert(context.Background(), "test-token", &caserver.CreateCertRequest{
		PublicKey:  pubKey,
		Connection: conn,
	})

	require.NoError(t, err)
	assert.Equal(t, sshcert.RawCertificate("ssh-ed25519-cert-v01@openssh.com AAAA..."), resp.Certificate)
}

// Discovery flow tests

func TestGetDiscoveryHitsDiscoveryPathUnauthenticated(t *testing.T) {
	var gotPaths []string
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/" {
			w.Header().Set("Link", `<discovery>; rel="https://epithet.dev/rel/auth"`)
			w.Header().Set("Content-type", "text/plain")
			w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"auth":{"issuer":"https://idp","client_id":"cid"}}`)
	}))
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: 0}})
	require.NoError(t, err)

	d, err := c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"/", "/discovery"}, gotPaths)
	require.Empty(t, gotAuth, "discovery must be anonymous")
	require.Equal(t, "https://idp", d.Auth.Issuer)
}

// newLinkCAServer serves a CA root that advertises discovery at the given
// relative target, plus the discovery document itself at discoveryPath.
func newLinkCAServer(t *testing.T, linkHeader string, discoveryPath string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if linkHeader != "" {
			w.Header().Set("Link", linkHeader)
		}
		w.Header().Set("Content-type", "text/plain")
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"))
	})
	mux.HandleFunc(discoveryPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"auth":{"issuer":"https://idp.example.com","client_id":"cid"}}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestGetDiscovery_FollowsLink(t *testing.T) {
	srv := newLinkCAServer(t,
		`<discovery>; rel="https://epithet.dev/rel/auth"`, "/discovery")

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: 0}})
	require.NoError(t, err)

	d, err := c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.NotNil(t, d.Auth)
	require.Equal(t, "https://idp.example.com", d.Auth.Issuer)
	require.Equal(t, "cid", d.Auth.ClientID)
}

// TestGetDiscovery_SlashlessCAURL is the RFC 3986 section 5 trap: a ca-url
// with no trailing slash must still resolve under itself. httptest's srv.URL
// is already slashless, so this is the direct form of the case.
func TestGetDiscovery_SlashlessCAURL(t *testing.T) {
	srv := newLinkCAServer(t,
		`<discovery>; rel="https://epithet.dev/rel/auth"`, "/discovery")

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: 0}})
	require.NoError(t, err)

	d, err := c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, "https://idp.example.com", d.Auth.Issuer)
}

// TestGetDiscovery_SlashTerminatedCAURL is the companion to
// TestGetDiscovery_SlashlessCAURL: an explicitly slash-terminated ca-url must
// resolve to the same discovery document as the slashless form.
func TestGetDiscovery_SlashTerminatedCAURL(t *testing.T) {
	srv := newLinkCAServer(t,
		`<discovery>; rel="https://epithet.dev/rel/auth"`, "/discovery")

	caURL := srv.URL + "/"
	c, err := caclient.New([]caclient.CAEndpoint{{URL: caURL, Priority: 0}})
	require.NoError(t, err)

	d, err := c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, "https://idp.example.com", d.Auth.Issuer)
	require.Equal(t, "cid", d.Auth.ClientID)
}

// TestGetDiscovery_NoLink is the version-skew case: an old CA emits no Link.
func TestGetDiscovery_NoLink(t *testing.T) {
	srv := newLinkCAServer(t, "", "/discovery")

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: 0}})
	require.NoError(t, err)

	_, err = c.GetDiscovery(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "did not advertise")
	require.Contains(t, err.Error(), srv.URL)
}

func TestGetDiscovery_RejectsCrossOriginLink(t *testing.T) {
	srv := newLinkCAServer(t,
		`<https://evil.example.com/d>; rel="https://epithet.dev/rel/auth"`, "/discovery")

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: 0}})
	require.NoError(t, err)

	_, err = c.GetDiscovery(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "different origin")
}

// TestGetDiscovery_LeavesCAURLUnchanged guards the "no requirement on the
// user" property: normalization is internal and must never be written back.
func TestGetDiscovery_LeavesCAURLUnchanged(t *testing.T) {
	srv := newLinkCAServer(t,
		`<discovery>; rel="https://epithet.dev/rel/auth"`, "/discovery")

	caURL := strings.TrimSuffix(srv.URL, "/")
	endpoints := []caclient.CAEndpoint{{URL: caURL, Priority: 0}}

	c, err := caclient.New(endpoints)
	require.NoError(t, err)

	_, err = c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, caURL, endpoints[0].URL)
}

// TestGetDiscovery_PrefixMountedCA is the central deployment case: the CA is
// mounted under a prefix that a proxy strips, so the CA itself only ever sees
// "/" and cannot know where it lives. The relative target still resolves.
// Note: ServeMux 301s "/epithet/ca" to "/epithet/ca/", so this test's value
// is the prefix-stripping coverage, not the slash-forcing rule — the redirect
// makes the slash path incidental here. See TestGetDiscovery_SlashlessCAURL
// and TestGetDiscovery_SlashTerminatedCAURL for that.
func TestGetDiscovery_PrefixMountedCA(t *testing.T) {
	inner := http.NewServeMux()
	inner.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<discovery>; rel="https://epithet.dev/rel/auth"`)
		w.Header().Set("Content-type", "text/plain")
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"))
	})
	inner.HandleFunc("/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"auth":{"issuer":"https://idp.example.com","client_id":"cid"}}`)
	})

	outer := http.NewServeMux()
	outer.Handle("/epithet/ca/", http.StripPrefix("/epithet/ca", inner))
	srv := httptest.NewServer(outer)
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL + "/epithet/ca", Priority: 0}})
	require.NoError(t, err)

	d, err := c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, "https://idp.example.com", d.Auth.Issuer)
}

// TestGetDiscovery_ResolvesAgainstFinalURLAfterRedirect proves the base is the
// URL the response came from, not the one configured. If the configured /old
// were used as the base, the target would resolve to /discovery and 404.
func TestGetDiscovery_ResolvesAgainstFinalURLAfterRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/new/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/new/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<discovery>; rel="https://epithet.dev/rel/auth"`)
		w.Header().Set("Content-type", "text/plain")
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"))
	})
	mux.HandleFunc("/new/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"auth":{"issuer":"https://idp.example.com","client_id":"cid"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL + "/old", Priority: 0}})
	require.NoError(t, err)

	d, err := c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, "https://idp.example.com", d.Auth.Issuer)
}

// TestGetDiscovery_RedirectToDifferentOriginRejected proves the same-origin
// check is anchored to the configured ca-url, not to wherever the root GET
// ends up. Server A (the configured CA) redirects the root GET to Server B,
// a different origin, which serves a relative Link target. If the check
// compared against the final (post-redirect) URL, the relative target would
// resolve under Server B and pass same-origin against itself, defeating the
// control in exactly the case it exists for.
func TestGetDiscovery_RedirectToDifferentOriginRejected(t *testing.T) {
	muxB := http.NewServeMux()
	muxB.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<discovery>; rel="https://epithet.dev/rel/auth"`)
		w.Header().Set("Content-type", "text/plain")
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"))
	})
	muxB.HandleFunc("/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"auth":{"issuer":"https://idp.example.com","client_id":"cid"}}`)
	})
	srvB := httptest.NewServer(muxB)
	defer srvB.Close()

	muxA := http.NewServeMux()
	muxA.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvB.URL+"/", http.StatusFound)
	})
	srvA := httptest.NewServer(muxA)
	defer srvA.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srvA.URL, Priority: 0}})
	require.NoError(t, err)

	_, err = c.GetDiscovery(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "different origin")
}

// TestGetDiscovery_ResolvedTargetServerError_ReturnsCAUnavailableError covers
// fetchDiscoveryDoc's status mapping, which TestGetDiscovery_ServerError_
// ReturnsCAUnavailableError no longer exercises now that the root GET is a
// separate request: here the root GET succeeds with a valid Link, and the
// resolved target itself returns 500.
func TestGetDiscovery_ResolvedTargetServerError_ReturnsCAUnavailableError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<discovery>; rel="https://epithet.dev/rel/auth"`)
		w.Header().Set("Content-type", "text/plain")
		w.Write([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"))
	})
	mux.HandleFunc("/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: caclient.DefaultPriority}})
	require.NoError(t, err)

	_, err = c.GetDiscovery(context.Background())
	require.Error(t, err)
	var allUnavail *caclient.AllCAsUnavailableError
	require.True(t, errors.As(err, &allUnavail), "expected AllCAsUnavailableError, got %T: %v", err, err)
	assert.Contains(t, allUnavail.Message, "CA unavailable")
}

func TestGetDiscovery_ServerError_ReturnsCAUnavailableError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: caclient.DefaultPriority}})
	require.NoError(t, err)

	// With a single endpoint, a 5xx trips the circuit breaker on the first
	// attempt, so the pool reports AllCAsUnavailableError rather than the
	// underlying CAUnavailableError directly (same behavior GetCert has
	// always had for 5xx responses).
	_, err = c.GetDiscovery(context.Background())
	require.Error(t, err)
	var allUnavail *caclient.AllCAsUnavailableError
	require.True(t, errors.As(err, &allUnavail), "expected AllCAsUnavailableError, got %T: %v", err, err)
	assert.Contains(t, allUnavail.Message, "CA unavailable")
}

func TestGetDiscovery_ClientError_ReturnsInvalidRequestError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("nope"))
	}))
	defer srv.Close()

	c, err := caclient.New([]caclient.CAEndpoint{{URL: srv.URL, Priority: caclient.DefaultPriority}})
	require.NoError(t, err)

	_, err = c.GetDiscovery(context.Background())
	require.Error(t, err)
	var invalidReq *caclient.InvalidRequestError
	require.True(t, errors.As(err, &invalidReq), "expected InvalidRequestError, got %T: %v", err, err)
}
