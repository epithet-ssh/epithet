// Package inventory resolves the entities a writ policy matches
// against: users (SCIM-shaped, RFC 7643) and hosts (name + labels +
// optional account list). The interface is the pluggability seam —
// today's implementation is a static file, later ones may be databases
// or live SCIM stores, and implementations are free to synthesize hosts
// (e.g. pattern-derived labels for short-lived VMs).
package inventory

import (
	"context"
	"fmt"

	"github.com/epithet-ssh/epithet/pkg/writ/eval"
	"golang.org/x/crypto/ssh"
)

// PrincipalMode selects how an allowed account@host tuple is represented in
// an issued SSH certificate.
type PrincipalMode string

const (
	// AccountNamePrincipals places the literal requested account name in the
	// certificate. It is compatible with ordinary OpenSSH CA configuration but
	// is not destination-bound.
	AccountNamePrincipals PrincipalMode = "account-name-principals"

	// HashedPrincipals derives a destination-bound principal from the host
	// identity public key and requested account name.
	HashedPrincipals PrincipalMode = "hashed-principals"
)

// Validate rejects unknown non-empty principal modes. Empty is the zero-value
// spelling of AccountNamePrincipals for compatibility with custom inventory
// implementations constructed in Go.
func (m PrincipalMode) Validate() error {
	switch m {
	case "", AccountNamePrincipals, HashedPrincipals:
		return nil
	default:
		return fmt.Errorf("unknown principal mode %q", m)
	}
}

// Effective returns the concrete mode represented by m.
func (m PrincipalMode) Effective() PrincipalMode {
	if m == "" {
		return AccountNamePrincipals
	}
	return m
}

// ResolvedHost carries both the host attributes consumed by Writ and, as the
// inventory grows, issuance metadata that must remain outside the pure policy
// model. Keeping those layers separate prevents certificate-construction
// details from becoming policy-language semantics.
type ResolvedHost struct {
	Policy        eval.Host
	PrincipalMode PrincipalMode
	IdentityKey   ssh.PublicKey
}

// Inventory looks up users and hosts at evaluation time.
//
// A (nil, nil) return means "no such entity" — a structural non-match
// that the evaluator turns into a 403, not an error. A non-nil error
// means the lookup itself failed and the evaluation must fail closed
// (500).
type Inventory interface {
	// LookupUser resolves an OIDC-bound identity to a user by comparing
	// it byte-for-byte against the configured SCIM identity attribute
	// (default userName).
	LookupUser(ctx context.Context, identity string) (*eval.User, error)

	// LookupHost resolves a requested host name. Callers must pass the
	// name through il.HostName first; implementations may synthesize a
	// host for names they can derive attributes for.
	LookupHost(ctx context.Context, name string) (*ResolvedHost, error)
}
