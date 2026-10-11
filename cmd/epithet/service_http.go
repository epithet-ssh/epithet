package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// readHeaderTimeout bounds how long a client gets to finish sending request
// headers. The CA and policy servers are internet-facing, so a bare
// http.Serve/ListenAndServe (no timeouts at all) lets a client that trickles
// bytes - or never finishes a request - pin a handler goroutine forever
// (slowloris). idleTimeout separately bounds how long a kept-alive
// connection may sit between requests.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 60 * time.Second
)

// listenAndServe starts an HTTP server on the given address with the
// timeouts above; ReadTimeout/WriteTimeout reuse tlsconfig.DefaultTimeout
// rather than a locally-duplicated literal.
// If addr starts with "unix://", it listens on a Unix domain socket.
// Otherwise it listens on TCP.
func listenAndServe(addr string, handler http.Handler) error {
	server := serviceHTTPServer(handler)
	ln, err := listenService(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return server.Serve(ln)
}

func serviceHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       tlsconfig.DefaultTimeout,
		WriteTimeout:      tlsconfig.DefaultTimeout,
		IdleTimeout:       idleTimeout,
	}
}

func listenService(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		return net.Listen("unix", path)
	}
	return net.Listen("tcp", addr)
}

// serveWithOIDC binds after local validation, then runs discovery alongside HTTP.
// A socket accepting connections means the child is alive, not OIDC-ready.
// Permanent discovery failures terminate the service; shutdown cancels and joins
// discovery so neither an HTTP attempt nor a backoff wait can outlive it.
func serveWithOIDC(addr string, handler http.Handler, validator *oidc.Validator, logger *slog.Logger) error {
	ln, err := listenService(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	server := serviceHTTPServer(serviceReadiness(handler, func(*http.Request) error { return validator.Ready() }))
	failure := make(chan error, 1)
	served := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := validator.Run(ctx, logger); err != nil && ctx.Err() == nil {
			failure <- err
		}
	}()
	go func() { defer wg.Done(); served <- server.Serve(ln) }()
	defer func() { cancel(); server.Close(); wg.Wait() }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-failure:
		return err
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// serviceReadiness exposes completed initialization through GET /readyz: 200
// when ready, or 503 with a reason while initialization is pending or a checked
// service is unavailable. These anonymous responses are uncached. Bootstrap
// provides the existing liveness signal. Combined readiness checks both CA and
// control through their private listeners; it does not probe the IdP. Bootstrap
// requests continue through the supplied handler while discovery is pending.
// The supplied check returns a fixed public reason, not dependency diagnostics.
func serviceReadiness(handler http.Handler, ready func(*http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			handler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := ready(r); err != nil {
			reason := err.Error()
			if errors.Is(err, oidc.ErrUnavailable) {
				reason = "OIDC discovery unavailable"
			}
			http.Error(w, reason, http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
}
