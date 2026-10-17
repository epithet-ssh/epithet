package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// RouterCLI is an internal subprocess interface used by ServerCLI to run a
// plain HTTP reverse proxy. Its command and flags are hidden from help.
// TLS termination belongs to the deployment's front end (for example Caddy);
// authentication stays in services.
type RouterCLI struct {
	Listen  string `hidden:"" help:"HTTP address to listen on" short:"l" default:"127.0.0.1:8080"`
	CA      string `hidden:"" placeholder:"URL" help:"Private CA Unix socket URL" name:"ca-backend" required:"true"`
	Control string `hidden:"" placeholder:"URL" help:"Private control Unix socket URL (enables /inventory and SCIM)" name:"control-backend"`
}

func (c *RouterCLI) Run(logger *slog.Logger) error {
	handler, closeIdle, err := newServiceRouter(c.CA, c.Control, logger)
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
	var inventory http.Handler
	var scim http.Handler
	var inventoryTransport *http.Transport
	if inventoryEndpoint != "" {
		proxy, transport, err := unixServiceProxy("inventory", inventoryEndpoint, "/manage", logger)
		if err != nil {
			caTransport.CloseIdleConnections()
			return nil, nil, err
		}
		proxy.Rewrite = func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = "inventory"
			r.Out.URL.Path = "/manage" + strings.TrimPrefix(r.In.URL.Path, "/inventory")
			r.Out.URL.RawPath = ""
		}
		inventory = proxy
		// Both routes use one private transport, but only SCIM preserves its path.
		scimProxy := *proxy
		scimProxy.Rewrite = func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = "inventory"
		}
		scim = &scimProxy
		inventoryTransport = transport
	}
	closeIdle := func() {
		caTransport.CloseIdleConnections()
		if inventoryTransport != nil {
			inventoryTransport.CloseIdleConnections()
		}
	}
	routes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only management and SCIM paths map to control. Fact lookups
		// are never public router destinations.
		if (r.URL.Path == "/inventory" || strings.HasPrefix(r.URL.Path, "/inventory/")) && inventory != nil {
			inventory.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/scim/v2/") && scim != nil {
			scim.ServeHTTP(w, r)
			return
		}
		ca.ServeHTTP(w, r)
	})
	// Combined readiness requires both public services to finish initialization.
	// Fact services are already initialized before their sockets are accepted by
	// the supervisor. These checks only contact private services, never the IdP.
	ready := func(r *http.Request) error {
		for _, backend := range []struct {
			name      string
			transport *http.Transport
		}{{"ca", caTransport}, {"control", inventoryTransport}} {
			if backend.transport == nil {
				continue
			}
			req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://"+backend.name+"/readyz", nil)
			if err != nil {
				return err
			}
			client := &http.Client{Transport: backend.transport, Timeout: tlsconfig.DefaultTimeout}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("%s service unavailable", backend.name)
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if readErr != nil {
				return fmt.Errorf("%s service unavailable", backend.name)
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s: %s", backend.name, strings.TrimSpace(string(body)))
			}
		}
		return nil
	}
	return serviceReadiness(routes, ready), closeIdle, nil
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
