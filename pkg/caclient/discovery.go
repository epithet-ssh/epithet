package caclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/breakerpool"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"golang.org/x/crypto/ssh"
)

// RootResponse is the anonymous bootstrap document returned by a CA URL.
// FinalURL is the URL after redirects and Links preserves every Link header
// field for consumers that implement advertised enrollment capabilities.
type RootResponse struct {
	PublicKey sshcert.RawPublicKey
	FinalURL  string
	Links     []string
}

// GetRoot fetches and validates the CA's anonymous bootstrap document, with
// automatic failover to backup CAs. The returned public key is canonical
// authorized-key text and the response's Link fields are retained verbatim.
func (c *Client) GetRoot(ctx context.Context) (*RootResponse, error) {
	result, err := c.pool.Execute(func(caURL string) (any, error) {
		if c.logger != nil {
			c.logger.Debug("GetRoot request", "url", caURL)
		}
		return c.doGetRoot(ctx, caURL)
	})

	if err != nil {
		var allUnavail *breakerpool.AllUnavailableError
		if errors.As(err, &allUnavail) {
			return nil, &AllCAsUnavailableError{Message: allUnavail.Error()}
		}
		return nil, err
	}
	return result.(*RootResponse), nil
}

func (c *Client) doGetRoot(ctx context.Context, caURL string) (*RootResponse, error) {
	if c.logger != nil {
		c.logger.Debug("http request", "method", "GET", "url", caURL)
	}

	rq, err := http.NewRequestWithContext(ctx, http.MethodGet, caURL, nil)
	if err != nil {
		return nil, &InvalidRequestError{Message: err.Error()}
	}

	start := time.Now()
	res, err := c.httpClient.Do(rq)
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "GET", "url", caURL, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, wire.MaxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > wire.MaxBodySize {
		return nil, &InvalidRequestError{Message: fmt.Sprintf("CA root response exceeds %d bytes", wire.MaxBodySize)}
	}

	if c.logger != nil {
		c.logger.Debug("http response", "method", "GET", "url", caURL, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	if res.StatusCode != http.StatusOK {
		message := fmt.Sprintf("GET %s returned %d: %s", caURL, res.StatusCode, string(body))
		if res.StatusCode >= 500 {
			return nil, &CAUnavailableError{Message: message}
		}
		return nil, &InvalidRequestError{Message: message}
	}

	key, err := sshcert.ParsePublicKey(sshcert.RawPublicKey(body))
	if err != nil {
		return nil, &InvalidRequestError{Message: fmt.Sprintf("CA at %s returned an invalid SSH public key: %v", caURL, err)}
	}
	finalURL := caURL
	if res.Request != nil && res.Request.URL != nil {
		finalURL = res.Request.URL.String()
	}
	return &RootResponse{
		PublicKey: sshcert.RawPublicKey(ssh.MarshalAuthorizedKey(key)),
		FinalURL:  finalURL,
		Links:     append([]string(nil), res.Header.Values("Link")...),
	}, nil
}

// DiscoveryResponse includes the auth document and public service addresses
// advertised by the same CA bootstrap response.
type DiscoveryResponse struct {
	wire.Discovery
	PublicCAURL  string
	InventoryURL string
}

// GetDiscovery fetches the CA's discovery document by following the Link
// header the CA advertises on its root GET, with automatic failover to
// backup CAs. The endpoint requires no authentication, so no token is sent.
// Callers are responsible for caching the result if they need to avoid
// repeated fetches.
func (c *Client) GetDiscovery(ctx context.Context) (*DiscoveryResponse, error) {
	result, err := c.pool.Execute(func(caURL string) (any, error) {
		if c.logger != nil {
			c.logger.Debug("GetDiscovery request", "url", caURL)
		}
		return c.doGetDiscovery(ctx, caURL)
	})

	if err != nil {
		var allUnavail *breakerpool.AllUnavailableError
		if errors.As(err, &allUnavail) {
			return nil, &AllCAsUnavailableError{Message: allUnavail.Error()}
		}
		return nil, err
	}
	return result.(*DiscoveryResponse), nil
}

// doGetDiscovery makes two unauthenticated GET requests to a CA: one to the CA
// URL itself, which advertises the location of the auth config with a relative
// Link target, and one to the resolved target. Neither request constructs a
// path, so the CA can be mounted anywhere.
func (c *Client) doGetDiscovery(ctx context.Context, caURL string) (*DiscoveryResponse, error) {
	final, links, err := c.fetchDiscoveryLinks(ctx, caURL)
	if err != nil {
		return nil, err
	}

	ref, _ := wire.FindLinkTarget(links, wire.RelAuth) // fetchDiscoveryLinks requires this relation.
	target, err := resolveLinkTarget(final, ref)
	if err != nil {
		return nil, err
	}

	// The same-origin check is anchored to the configured ca-url, not to
	// final: a redirect can legitimately move the resolution base (see
	// fetchDiscoveryLinks), but it must not be able to walk the origin check
	// off along with it, or a redirect to an attacker's origin defeats the
	// control by comparing that origin to itself.
	configured, err := url.Parse(caURL)
	if err != nil {
		return nil, err
	}
	if !sameOrigin(configured, target) {
		return nil, &InvalidRequestError{Message: fmt.Sprintf("CA at %s advertised discovery at a different origin (%s)", caURL, target)}
	}

	inventoryURL, err := InventoryURL(&RootResponse{FinalURL: final.String(), Links: links.Values("Link")}, c.tlsConfig)
	if err != nil {
		return nil, err
	}
	discovery, err := c.fetchDiscoveryDoc(ctx, target.String())
	if err != nil {
		return nil, err
	}
	return &DiscoveryResponse{Discovery: *discovery, PublicCAURL: final.String(), InventoryURL: inventoryURL}, nil
}

// fetchDiscoveryLinks GETs the CA URL and returns the URL the response actually
// came from (which differs from caURL if redirected) along with the Link headers
// advertising its public service endpoints.
func (c *Client) fetchDiscoveryLinks(ctx context.Context, caURL string) (*url.URL, http.Header, error) {
	if c.logger != nil {
		c.logger.Debug("http request", "method", "GET", "url", caURL)
	}

	rq, err := http.NewRequest("GET", caURL, nil)
	if err != nil {
		return nil, nil, err
	}

	start := time.Now()
	res, err := c.httpClient.Do(rq.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "GET", "url", caURL, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return nil, nil, err
	}
	defer res.Body.Close()
	// The body is the CA public key; discovery does not need it, but it must
	// be drained for connection reuse.
	io.Copy(io.Discard, io.LimitReader(res.Body, wire.MaxBodySize))

	if c.logger != nil {
		c.logger.Debug("http response", "method", "GET", "url", caURL, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	if res.StatusCode != http.StatusOK {
		if res.StatusCode >= 500 {
			return nil, nil, &CAUnavailableError{Message: fmt.Sprintf("GET %s returned %d", caURL, res.StatusCode)}
		}
		return nil, nil, &InvalidRequestError{Message: fmt.Sprintf("GET %s returned %d", caURL, res.StatusCode)}
	}

	_, ok := wire.FindLinkTarget(res.Header, wire.RelAuth)
	if !ok {
		return nil, nil, &InvalidRequestError{Message: fmt.Sprintf("CA at %s did not advertise its auth config (no Link with rel=%q); the CA is older than this client and must be upgraded", caURL, wire.RelAuth)}
	}

	// Resolve against where the response came from, not where it was sent, so
	// a redirect cannot silently shift the base.
	final := res.Request.URL

	return final, res.Header, nil
}

// fetchDiscoveryDoc GETs the resolved discovery URL and decodes it.
func (c *Client) fetchDiscoveryDoc(ctx context.Context, discoveryURL string) (*wire.Discovery, error) {
	if c.logger != nil {
		c.logger.Debug("http request", "method", "GET", "url", discoveryURL)
	}

	rq, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	res, err := c.httpClient.Do(rq.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "GET", "url", discoveryURL, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return nil, err
	}
	defer res.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(res.Body, wire.MaxBodySize+1))
	if err != nil {
		return nil, err
	}

	// Check if the CA's response exceeds the limit before trusting its contents.
	if len(respBody) > wire.MaxBodySize {
		return nil, fmt.Errorf("response exceeds %d bytes", wire.MaxBodySize)
	}

	if c.logger != nil {
		c.logger.Debug("http response", "method", "GET", "url", discoveryURL, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	if res.StatusCode != http.StatusOK {
		// The discovery endpoint is anonymous, so there is no 401 case here.
		if res.StatusCode >= 500 {
			return nil, &CAUnavailableError{Message: string(respBody)}
		}
		return nil, &InvalidRequestError{Message: string(respBody)}
	}

	var discovery wire.Discovery
	if err := json.Unmarshal(respBody, &discovery); err != nil {
		return nil, fmt.Errorf("failed to unmarshal discovery response: %w", err)
	}

	return &discovery, nil
}

// InventoryURL follows only the configured CA's explicit inventory relation.
// Unlike auth discovery, inventory may intentionally be on another HTTPS origin.
// No credentials are sent during discovery, or forwarded through redirects.
func InventoryURL(root *RootResponse, cfg tlsconfig.Config) (string, error) {
	headers := http.Header{}
	headers["Link"] = root.Links
	ref, ok := wire.FindLinkTarget(headers, wire.RelControl)
	if !ok {
		return "", nil
	}
	base, err := url.Parse(root.FinalURL)
	if err != nil {
		return "", err
	}
	target, err := resolveLinkTarget(base, ref)
	if err != nil {
		return "", err
	}
	if target.User != nil || target.Fragment != "" || target.Host == "" || (target.Scheme != "https" && target.Scheme != "http") {
		return "", fmt.Errorf("invalid advertised inventory URL")
	}
	if err = cfg.ValidateURL(target.String()); err != nil {
		return "", err
	}
	return target.String(), nil
}

// resolveLinkTarget resolves a Link target reference against the URL a
// response actually came from.
//
// The base is that URL's scheme, host, and path only, with a trailing slash
// forced: ca-url names a collection, and RFC 3986 5 would otherwise drop its
// last segment ("/epithet/ca" + "discovery" resolves to "/epithet/discovery").
// Query and fragment are dropped because neither is meaningful for a
// collection base. This normalization is internal — the configured ca-url is
// never rewritten.
func resolveLinkTarget(final *url.URL, ref string) (*url.URL, error) {
	parsed, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("invalid Link target %q: %w", ref, err)
	}

	base := &url.URL{Scheme: final.Scheme, Host: final.Host, Path: final.Path}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}

	return base.ResolveReference(parsed), nil
}

// sameOrigin reports whether a and b share scheme, host, and port. A Link
// target is a URI-Reference, so an absolute cross-host value is legal; we
// reject it to keep TLS trust anchored to the configured host.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}
