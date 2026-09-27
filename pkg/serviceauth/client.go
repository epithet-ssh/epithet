package serviceauth

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Client owns a private service transport and signs each complete request.
// Endpoints are service roots; redirects never receive service credentials.
type Client struct {
	endpoint string
	http     *http.Client
	signer   *Signer
}

func NewClient(endpoint string, key sshcert.RawPrivateKey, audience string, cfg tlsconfig.Config) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("service URL cannot contain credentials, query, or fragment")
	}
	if u.Scheme != "unix" && ((u.Scheme != "https" && u.Scheme != "http") || u.Host == "") {
		return nil, fmt.Errorf("service URL must use https:// or unix://")
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
			return nil, fmt.Errorf("service socket path is required")
		}
		client.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}
		endpoint = "http://service"
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	signer, err := NewSignerFor(key, audience)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: strings.TrimRight(endpoint, "/"), http: client, signer: signer}, nil
}

// Do binds actor only for human administration; pass an empty string for reads
// and machine operations. The caller owns the returned response body.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body []byte, actor string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = query.Encode()
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Cache-Control", "no-store")
	if err := c.signer.AuthorizeActor(req, body, actor); err != nil {
		return nil, err
	}
	return c.http.Do(req)
}
