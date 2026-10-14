// Package inventory owns managed host facts, enrollment, patterns, and storage.
package inventory

import (
	"context"
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/principal"
)

// PrincipalMode selects how an allowed account@host tuple is represented in
// an issued SSH certificate.
type PrincipalMode string

const (
	// AccountNamePrincipals places the literal requested account name in the
	// certificate. It is compatible with ordinary OpenSSH CA configuration but
	// is not destination-bound.
	AccountNamePrincipals PrincipalMode = "account-name"

	// EpithetPrincipalV1 derives a destination-bound v1 principal from the
	// principal realm and requested account name.
	EpithetPrincipalV1 PrincipalMode = principal.SchemeV1
)

// Validate rejects unknown non-empty principal modes. Empty is the zero-value
// spelling of AccountNamePrincipals for compatibility with custom inventory
// implementations constructed in Go.
func (m PrincipalMode) Validate() error {
	switch m {
	case "", AccountNamePrincipals, EpithetPrincipalV1:
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

// Host enrollment statuses. Status remains a string in storage and API records.
const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusDenied  = "denied"
)

// Host contains inventory names, authorization facts, and enrollment metadata.
// Names may be exact hostnames or wildcard expressions. Lookup prefers exact
// names; wildcard matches supply facts for the requested hostname.
type Host struct {
	ID            string            `yaml:"-"`
	Revision      uint64            `yaml:"-"`
	CreatedAt     time.Time         `yaml:"-"`
	UpdatedAt     time.Time         `yaml:"-"`
	Status        string            `yaml:"-"`
	Names         []string          `yaml:"names"`
	Labels        map[string]string `yaml:"labels"`
	Accounts      []string          `yaml:"accounts"`
	PrincipalMode PrincipalMode     `yaml:"principal-mode"`
	Realm         principal.Realm   `yaml:"realm,omitempty"`
}

// Hosts resolves machines independently of the user directory.
// LookupHost returns host facts. A missing host returns nil; lookup failures
// return an error. Read consistency and visibility are backend-specific.
// Managed lookups prefer exact names over patterns and return ErrConflict for
// multiple matching active patterns.
type Hosts interface {
	LookupHost(context.Context, string) (*Host, error)
}
