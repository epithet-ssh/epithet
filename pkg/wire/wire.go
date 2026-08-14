// Package wire holds every type that crosses a process boundary (CA,
// policy server, CA client). Consolidating these shapes here means later
// changes to the wire format only need to happen in one place.
package wire

import (
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
)

// CertParams are the certificate parameters decided by the policy server.
type CertParams struct {
	Identity   string            `json:"identity"`
	Names      []string          `json:"principals"`
	Expiration time.Duration     `json:"expiration"`
	Extensions map[string]string `json:"extensions"`
}

// PolicyRequest is the CA→policy-server cert evaluation request body.
type PolicyRequest struct {
	Token      string            `json:"token"`
	Connection policy.Connection `json:"connection"`
}

// PolicyResponse is the policy server's answer to a PolicyRequest.
type PolicyResponse struct {
	CertParams CertParams    `json:"certParams"`
	Policy     policy.Policy `json:"policy"`
}

// AuthConfig tells a client how to authenticate. Shape matches today's
// BootstrapAuth; Type/Command/Scopes are removed by later tasks.
type AuthConfig struct {
	Type         string   `json:"type"`
	Issuer       string   `json:"issuer,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Command      string   `json:"command,omitempty"`
}

// Discovery is the discovery document.
type Discovery struct {
	Auth          *AuthConfig `json:"auth,omitempty"`
	MatchPatterns []string    `json:"matchPatterns,omitempty"`

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
