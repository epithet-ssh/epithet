package facts

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// transport owns signed HTTP exchanges for both client roles. It never escapes
// the package; callers receive decoded domain results with no body to close.
type transport struct {
	endpoint string
	http     *http.Client
	signer   *Signer
}

func newTransport(endpoint string, key sshcert.RawPrivateKey, audience string, cfg tlsconfig.Config) (*transport, error) {
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
	return &transport{endpoint: strings.TrimRight(endpoint, "/"), http: client, signer: signer}, nil
}

// exchange is the private wire result. SCIM needs the listed response metadata;
// other operations decode the body and translate status into domain errors.
type exchange struct {
	status                                    int
	body                                      []byte
	contentType, etag, location, authenticate string
}

func (c *transport) request(ctx context.Context, method, path string, query url.Values, body []byte, actor string, limit int64) (*exchange, error) {
	if c == nil {
		return nil, &ServiceError{Status: http.StatusNotFound, Message: "requested inventory capability is not configured"}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	req.URL.RawQuery = query.Encode()
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Cache-Control", "no-store")
	if err := c.signer.AuthorizeActor(req, body, actor); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: service response exceeds size limit", ErrUnavailable)
	}
	return &exchange{status: resp.StatusCode, body: data, contentType: resp.Header.Get("Content-Type"), etag: resp.Header.Get("ETag"), location: resp.Header.Get("Location"), authenticate: resp.Header.Get("WWW-Authenticate")}, nil
}
