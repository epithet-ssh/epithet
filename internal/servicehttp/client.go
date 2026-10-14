// Package servicehttp owns signed HTTP exchanges for service clients.
// Resource discovery, protocol statuses and domain errors belong to callers.
package servicehttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Client owns connection setup, signing and bounded response reads.
// Its HTTP client never follows redirects.
type Client struct {
	endpoint string
	http     *http.Client
	signer   *serviceauth.Signer
	tls      tlsconfig.Config
	unix     bool
}

// New uses unixPath as the endpoint path for Unix sockets; HTTP URLs retain
// their configured path. The audience identifies the receiving service.
func New(endpoint, unixPath string, key sshcert.RawPrivateKey, audience string, cfg tlsconfig.Config) (*Client, error) {
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
		endpoint = "http://service" + unixPath
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	signer, err := serviceauth.NewSignerFor(key, audience)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: endpoint, http: client, signer: signer, tls: cfg, unix: u.Scheme == "unix"}, nil
}

// Endpoint is the configured HTTP URL, or the local route selected for a socket.
func (c *Client) Endpoint() string { return c.endpoint }

// Resolve resolves a discovered reference against Endpoint and enforces this
// client's transport policy. Unix references must stay on the local service;
// HTTP references must satisfy the configured TLS policy.
func (c *Client) Resolve(raw string) (*url.URL, error) {
	reference, err := url.Parse(raw)
	if err != nil {
		// Discovered URLs can contain credentials in template parameters.
		return nil, fmt.Errorf("invalid service resource URL")
	}
	base, _ := url.Parse(c.endpoint)
	target := base.ResolveReference(reference)
	if target.User != nil || target.Fragment != "" || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("invalid service resource URL")
	}
	if c.unix {
		if target.Scheme != base.Scheme || target.Host != base.Host {
			return nil, fmt.Errorf("service URL leaves Unix service")
		}
	} else if err := c.tls.ValidateURL(target.String()); err != nil {
		return nil, err
	}
	return target, nil
}

// Request carries exactly the operation and metadata covered by the signature.
// URL is a complete target; discovered references must first pass Resolve.
// Actor is empty for service operations and identifies the public caller otherwise.
type Request struct {
	Method, URL, Actor, ContentType, IfMatch string
	Body                                     []byte
}

// Response owns its buffered body; callers have nothing to close. HTTP failure
// statuses are responses, leaving their interpretation to each protocol.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Do signs the request, sends it without following redirects, and reads at most
// limit bytes. ContentType is explicit, including for requests without a body.
func (c *Client) Do(ctx context.Context, request Request, limit int64) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(request.Body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("If-Match", request.IfMatch)
	if request.ContentType != "" {
		req.Header.Set("Content-Type", request.ContentType)
	}
	req.Header.Set("Cache-Control", "no-store")
	if err := c.signer.AuthorizeActor(req, request.Body, request.Actor); err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// A discovered token revocation URL contains the credential. net/http's
		// url.Error includes that URL; retain its cause without exposing it.
		var requestError *url.Error
		if errors.As(err, &requestError) {
			err = requestError.Err
		}
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("service response exceeds size limit")
	}
	return &Response{Header: resp.Header.Clone(), Status: resp.StatusCode, Body: data}, nil
}
