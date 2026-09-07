// Package wire holds every type that crosses a process boundary (CA,
// policy server, CA client). Consolidating these shapes here means later
// changes to the wire format only need to happen in one place.
package wire

import (
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
)

// MaxBodySize is the maximum request body and trusted-peer response body size.
// Real OIDC ID tokens with group claims run 4-8 KiB; 64 KiB leaves an order
// of magnitude of headroom before truncation.
const MaxBodySize = 64 * 1024

// CertParams are the certificate parameters decided by the policy server.
type CertParams struct {
	Identity   string            `json:"identity"`
	Names      []string          `json:"principals"`
	Expiration time.Duration     `json:"expiration"`
	Extensions map[string]string `json:"extensions"`

	// NotAfter is an absolute ceiling on certificate validity, derived from
	// the auth token's expiry. It travels as an absolute time (not a
	// duration) because a duration would decay during the time between
	// policy evaluation and CA signing. Zero value means no ceiling.
	NotAfter time.Time `json:"notAfter,omitempty"`
}

// PolicyRequest is the CA→policy-server cert evaluation request body.
type PolicyRequest struct {
	Token      string            `json:"token"`
	Connection policy.Connection `json:"connection"`
}

// PolicyResponse is the policy server's answer to a PolicyRequest. It carries
// only the cert parameters for this one connection - there is no
// authorization map on the wire, since certs are minted per-connection and
// never cached or reused by the client.
type PolicyResponse struct {
	CertParams CertParams `json:"certParams"`
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
