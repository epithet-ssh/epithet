// Package inventory owns host facts and static loading. The static loader
// also implements the independent directory.Directory user lookup interface.
package inventory

import (
	"context"
	"fmt"

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
	// principal domain and requested account name.
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

// ResolvedHost carries both the authorization resource consumed by Writ and
// issuance metadata that must remain outside the pure policy model. For a
// shared named domain, Policy.Name is the domain rather than the requested
// hostname because the resulting credential is portable across every member.
type ResolvedHost struct {
	Policy        Host
	PrincipalMode PrincipalMode
	Domain        principal.Domain
}

// Host contains authorization attributes, separate from principal metadata.
type Host struct {
	Name     string
	Labels   map[string]string
	Accounts []string
}

// Hosts resolves machines independently of the user directory.
type Hosts interface {
	LookupHost(context.Context, string) (*ResolvedHost, error)
}
