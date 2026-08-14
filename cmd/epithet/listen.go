package main

import (
	"net"
	"net/http"
	"strings"
	"time"

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
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       tlsconfig.DefaultTimeout,
		WriteTimeout:      tlsconfig.DefaultTimeout,
		IdleTimeout:       idleTimeout,
	}

	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		ln, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		defer ln.Close()
		return server.Serve(ln)
	}

	server.Addr = addr
	return server.ListenAndServe()
}
