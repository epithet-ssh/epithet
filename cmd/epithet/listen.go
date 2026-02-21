package main

import (
	"net"
	"net/http"
	"strings"
)

// listenAndServe starts an HTTP server on the given address.
// If addr starts with "unix://", it listens on a Unix domain socket.
// Otherwise it delegates to http.ListenAndServe for TCP.
func listenAndServe(addr string, handler http.Handler) error {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		ln, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		defer ln.Close()
		return http.Serve(ln, handler)
	}
	return http.ListenAndServe(addr, handler)
}
