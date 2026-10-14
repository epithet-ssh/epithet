package caclient

import (
	"fmt"
	"net/url"
	"strings"
)

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
