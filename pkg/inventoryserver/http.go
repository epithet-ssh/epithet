// Package inventoryserver serves CA-authenticated resolution reads. It exposes
// no administration or enrollment operations in the static implementation.
package inventoryserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

type Config struct {
	CAPublicKey sshcert.RawPublicKey
	Resolver    *Resolver
	Validator   *oidc.Validator
	Discovery   *wire.Discovery
}

// NewHandler dispatches GET discovery and POST resolution by method at the
// configured endpoint. A mounting proxy must preserve the signed host and path.
func NewHandler(config Config) (http.Handler, error) {
	key, resolver := config.CAPublicKey, config.Resolver
	verifier, err := serviceauth.NewVerifierFor(key, serviceauth.InventoryAudience)
	if err != nil {
		return nil, err
	}
	if resolver == nil || config.Validator == nil {
		return nil, fmt.Errorf("inventory resolver and OIDC validator are required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		defer r.Body.Close()
		body, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxBodySize+1))
		if err != nil {
			http.Error(w, "reading inventory request", 400)
			return
		}
		if len(body) > wire.MaxBodySize {
			http.Error(w, "inventory request too large", 413)
			return
		}
		if err := verifier.Verify(r, body); err != nil {
			http.Error(w, "invalid inventory service authentication", 403)
			return
		}
		// Query parameters are not part of this RPC or the service-token binding.
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			http.NotFound(w, r)
			return
		}
		if r.Method == "GET" {
			if config.Discovery == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "max-age=300")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config.Discovery)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		var req inventoryapi.ResolveRequest
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid inventory request", 400)
			return
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			http.Error(w, "invalid inventory request", 400)
			return
		}
		if req.Host == "" || req.Host != hostpattern.NormalizeName(req.Host) {
			http.Error(w, "invalid inventory host", 400)
			return
		}
		claims, err := config.Validator.Validate(r.Context(), req.Token)
		if err != nil {
			http.Error(w, "invalid authentication token", 401)
			return
		}
		resp, err := resolver.Resolve(r.Context(), facts.Authentication{ID: claims.UserID, ExpiresAt: claims.ExpiresAt}, req.Host)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if err := resp.Validate(req.Host); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		data, err := json.Marshal(resp)
		if err != nil || len(data) > wire.MaxBodySize {
			http.Error(w, "invalid or oversized inventory response", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}), nil
}

type Client struct {
	url    string
	http   *http.Client
	signer *serviceauth.Signer
}

// NewClient uses a separate transport for inventory so a Unix policy socket
// cannot accidentally receive inventory requests. Redirects are never followed.
func NewClient(endpoint string, key sshcert.RawPrivateKey, cfg tlsconfig.Config) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("inventory URL cannot contain credentials, query, or fragment")
	}
	if u.Scheme != "unix" && ((u.Scheme != "https" && u.Scheme != "http") || u.Host == "") {
		return nil, fmt.Errorf("inventory URL must use https:// or unix://")
	}
	if err := cfg.ValidateURL(endpoint); err != nil {
		return nil, err
	}
	client, err := tlsconfig.NewHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	if path, ok := strings.CutPrefix(endpoint, "unix://"); ok {
		if path == "" {
			return nil, fmt.Errorf("inventory socket path is required")
		}
		client.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}
		endpoint = "http://inventory"
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	signer, err := serviceauth.NewSignerFor(key, serviceauth.InventoryAudience)
	if err != nil {
		return nil, err
	}
	return &Client{url: endpoint, http: client, signer: signer}, nil
}

func (c *Client) Resolve(ctx context.Context, req inventoryapi.ResolveRequest) (*inventoryapi.Resolution, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if len(body) > wire.MaxBodySize {
		return nil, fmt.Errorf("inventory request too large")
	}
	request, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err := c.signer.Authorize(request, body); err != nil {
		return nil, err
	}
	resp, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("inventory resolution failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, wire.MaxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > wire.MaxBodySize {
		return nil, fmt.Errorf("inventory response too large")
	}
	if resp.StatusCode == 401 {
		return nil, &wire.PolicyError{StatusCode: 401, Message: "invalid authentication token"}
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("inventory resolution returned HTTP %d", resp.StatusCode)
	}
	var result inventoryapi.Resolution
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid inventory response: %w", err)
	}
	if err := result.Validate(req.Host); err != nil {
		return nil, err
	}
	return &result, nil
}

// FetchDiscovery reads inventory-owned login configuration using service authentication.
func (c *Client) FetchDiscovery(ctx context.Context) (*wire.Discovery, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.url, nil)
	if err != nil {
		return nil, err
	}
	if err := c.signer.Authorize(req, nil); err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching inventory discovery: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, wire.MaxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > wire.MaxBodySize {
		return nil, fmt.Errorf("inventory discovery response too large")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("inventory returned HTTP %d for discovery", resp.StatusCode)
	}
	var result wire.Discovery
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid inventory discovery: %w", err)
	}
	result.CacheControl = resp.Header.Get("Cache-Control")
	return &result, nil
}
