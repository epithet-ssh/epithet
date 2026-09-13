package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func routerTestSocket(t *testing.T, handler http.Handler) string {
	t.Helper()
	// macOS Unix sockets need shorter paths than t.TempDir normally provides.
	dir, err := os.MkdirTemp("/tmp", "er")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "service.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return "unix://" + path
}

func TestRouterForwardsThroughUnixSockets(t *testing.T) {
	type received struct {
		Service, Method, URI, Host, Authorization, Cookie, Body string
		Forwarded, HopByHop                                     string
	}
	backend := func(service string, status int) string {
		return routerTestSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Add("Link", `<inventory>; rel="https://epithet.dev/rel/inventory"`)
			w.Header().Add("Link", `<discovery>; rel="https://epithet.dev/rel/auth"`)
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(received{service, r.Method, r.RequestURI, r.Host,
				r.Header.Get("Authorization"), r.Header.Get("Cookie"), string(body),
				r.Header.Get("Forwarded") + r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Hop")})
		}))
	}
	ca := backend("ca", http.StatusCreated)
	inventory := backend("inventory", http.StatusAccepted)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, enabled := range []bool{true, false} {
		endpoint := ""
		if enabled {
			endpoint = inventory
		}
		router, closeIdle, err := newServiceRouter(ca, endpoint, logger)
		require.NoError(t, err)
		t.Cleanup(closeIdle)
		for _, path := range []string{"/", "/discovery?x=1", "/inventory?x=1", "/inventory/resolve", "/resolve", "/manage", "/policy", "/a%2Fb"} {
			for _, method := range []string{"GET", "POST"} {
				req := httptest.NewRequest(method, "http://ca.example"+path, strings.NewReader("proposal"))
				req.Header.Set("Authorization", "Bearer client-token")
				req.Header.Set("Cookie", "session=client")
				req.Header.Set("Forwarded", "for=untrusted")
				req.Header.Set("X-Forwarded-For", "untrusted")
				req.Header.Set("Connection", "X-Hop")
				req.Header.Set("X-Hop", "private")
				out := httptest.NewRecorder()
				router.ServeHTTP(out, req)
				wantService, wantURI, wantStatus := "ca", path, http.StatusCreated
				if enabled && strings.HasPrefix(path, "/inventory?") {
					wantService, wantURI, wantStatus = "inventory", "/manage?x=1", http.StatusAccepted
				}
				require.Equal(t, wantStatus, out.Code, path)
				var got received
				require.NoError(t, json.Unmarshal(out.Body.Bytes(), &got))
				require.Equal(t, received{Service: wantService, Method: method, URI: wantURI, Host: "ca.example",
					Authorization: "Bearer client-token", Cookie: "session=client", Body: "proposal"}, got)
				require.Len(t, out.Header().Values("Link"), 2)
				require.Equal(t, "no-store", out.Header().Get("Cache-Control"))
			}
		}
	}
}

func TestRouterUnavailableInventoryReturnsBadGateway(t *testing.T) {
	ca := routerTestSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	router, closeIdle, err := newServiceRouter(ca, ca+".missing", slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	defer closeIdle()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("POST", "http://ca.example/inventory", nil))
	require.Equal(t, http.StatusBadGateway, response.Code, "must not fall back to CA")
	require.Equal(t, "upstream unavailable\n", response.Body.String())
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("GET", "http://ca.example/", nil))
	require.Equal(t, http.StatusOK, response.Code, "CA remains independently reachable")
}

func TestRouterRequiresPrivateUnixBackends(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, endpoint := range []string{"", "https://example.com", "http://localhost", "unix://relative", "unix://"} {
		_, _, err := newServiceRouter(endpoint, "", logger)
		require.Error(t, err)
		if endpoint != "" {
			_, _, err = newServiceRouter("unix:///tmp/ca.sock", endpoint, logger)
			require.Error(t, err)
		}
	}
}
