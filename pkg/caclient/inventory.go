package caclient

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// InventoryURL follows only the configured CA's explicit inventory relation.
// Unlike auth discovery, inventory may intentionally be on another HTTPS origin.
// No credentials are sent during discovery, or forwarded through redirects.
func InventoryURL(root *RootResponse, cfg tlsconfig.Config) (string, error) {
	headers := http.Header{}
	headers["Link"] = root.Links
	ref, ok := findLinkTarget(headers, wire.RelInventory)
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
