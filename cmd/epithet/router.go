package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// RouterCLI is a plain HTTP reverse proxy. TLS termination belongs to the
// deployment's front end (for example Caddy); authentication stays in services.
type RouterCLI struct {
	Listen    string `help:"HTTP address to listen on" short:"l" default:"127.0.0.1:8080"`
	CA        string `help:"Private CA Unix socket URL" name:"ca" required:"true"`
	Inventory string `help:"Private inventory Unix socket URL (enables /inventory)" name:"inventory"`
}

func (c *RouterCLI) Run(logger *slog.Logger) error {
	handler, closeIdle, err := newServiceRouter(c.CA, c.Inventory, logger)
	if err != nil {
		return err
	}
	defer closeIdle()
	logger.Info("listening", "address", c.Listen)
	return listenAndServe(c.Listen, handler)
}

func newServiceRouter(caEndpoint, inventoryEndpoint string, logger *slog.Logger) (http.Handler, func(), error) {
	ca, caTransport, err := unixServiceProxy("ca", caEndpoint, "", logger)
	if err != nil {
		return nil, nil, err
	}
	closeIdle := caTransport.CloseIdleConnections
	var inventory http.Handler
	if inventoryEndpoint != "" {
		proxy, transport, err := unixServiceProxy("inventory", inventoryEndpoint, "/manage", logger)
		if err != nil {
			closeIdle()
			return nil, nil, err
		}
		inventory = proxy
		closeIdle = func() { caTransport.CloseIdleConnections(); transport.CloseIdleConnections() }
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only this exact public path maps to inventory. Its private resolver
		// endpoints and policy service are never public router destinations.
		if r.URL.Path == "/inventory" && inventory != nil {
			inventory.ServeHTTP(w, r)
			return
		}
		ca.ServeHTTP(w, r)
	}), closeIdle, nil
}

func unixServiceProxy(service, endpoint, targetPath string, logger *slog.Logger) (*httputil.ReverseProxy, *http.Transport, error) {
	path, ok := strings.CutPrefix(endpoint, "unix://")
	if !ok || !filepath.IsAbs(path) {
		return nil, nil, fmt.Errorf("%s router backend requires an absolute Unix socket URL", service)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: tlsconfig.DefaultTimeout}).DialContext(ctx, "unix", path)
		},
		ResponseHeaderTimeout: tlsconfig.DefaultTimeout,
		IdleConnTimeout:       idleTimeout,
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = service
			if targetPath != "" {
				r.Out.URL.Path = targetPath
				r.Out.URL.RawPath = ""
			}
			// Keep the public Host and client Authorization. ReverseProxy strips
			// forwarded and hop-by-hop headers; no service credentials are added.
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("proxy request failed", "service", service, "error", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return proxy, transport, nil
}
