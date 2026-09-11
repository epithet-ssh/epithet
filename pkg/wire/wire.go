// Package wire holds every type that crosses a process boundary (CA,
// policy server, CA client). Consolidating these shapes here means later
// changes to the wire format only need to happen in one place.
package wire

import (
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/policy"
)

// MaxBodySize is the maximum request body and trusted-peer response body size.
// Real OIDC ID tokens with group claims run 4-8 KiB; 64 KiB leaves an order
// of magnitude of headroom before truncation.
const MaxBodySize = 64 * 1024

// PolicyRequest is the CA→policy-server cert evaluation request body.
type PolicyRequest struct {
	Facts      *inventoryapi.Resolution `json:"facts"`
	Connection policy.Connection        `json:"connection"`
}

// PolicyResponse grants this one connection with policy-owned limits. HTTP
// 200 means authorized; other outcomes use PolicyError. CA constructs the
// certificate identity and principal from its original inventory facts.
type PolicyResponse struct {
	// TTL is a positive duration in nanoseconds, measured from CA signing.
	TTL        time.Duration     `json:"ttl"`
	Extensions map[string]string `json:"extensions"`
	// NotAfter is an optional absolute policy deadline. It may tighten, but
	// never extend, the authentication expiry independently enforced by CA.
	NotAfter          time.Time `json:"notAfter,omitzero"`
	PolicyID          string    `json:"policyId,omitempty"`
	DirectoryRevision string    `json:"directoryRevision,omitempty"`
	InventoryRevision string    `json:"inventoryRevision,omitempty"`
}

// AuthConfig tells a client how to authenticate: OIDC issuer and client
// credentials. This is the only auth mechanism epithet supports, so there is
// no type discriminator.
type AuthConfig struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// Discovery is the discovery document: the anonymous bootstrap endpoint's
// entire payload. It carries only auth config — no server-advertised match
// patterns, since gating on those was removed.
type Discovery struct {
	Auth *AuthConfig `json:"auth,omitempty"`

	// CacheControl carries the upstream Cache-Control header; never serialized.
	CacheControl string `json:"-"`
}

// PolicyError is a policy-server error with its HTTP status.
type PolicyError struct {
	StatusCode int
	Message    string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("policy error %d: %s", e.StatusCode, e.Message)
}
