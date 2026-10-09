// Package inventory owns host facts and static loading. The static loader
// also implements the independent directory.Directory user lookup interface.
package inventory

import (
	"context"
	"fmt"
	"maps"
	"slices"

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

// ResolvedHost carries both the authorization resource consumed by Writ and
// issuance metadata that must remain outside the pure policy model. Policy.Names
// always contains the host's names, independent of its principal mode or realm.
type ResolvedHost struct {
	Policy        Host
	PrincipalMode PrincipalMode
	Realm         principal.Realm
}

// Host contains authorization attributes, separate from principal metadata.
type Host struct {
	Names    []string
	Labels   map[string]string
	Accounts []string
}

// Hosts resolves machines independently of the user directory.
// LookupHost returns the host and the revision of the inventory used to resolve
// it from one coherent read. A missing host returns nil with a nonempty revision;
// lookup failures return an error.
type Hosts interface {
	LookupHost(context.Context, string) (*ResolvedHost, string, error)
}

// sameAuthorization compares the authorization attributes shared by all realm members.
// Account order is irrelevant; unrestricted (nil) differs from no accounts ([]).
func sameAuthorization(previousLabels map[string]string, previousAccounts []string, labels map[string]string, accounts []string) bool {
	if !maps.Equal(previousLabels, labels) || (previousAccounts == nil) != (accounts == nil) {
		return false
	}
	previous, proposed := slices.Clone(previousAccounts), slices.Clone(accounts)
	slices.Sort(previous)
	slices.Sort(proposed)
	return slices.Equal(previous, proposed)
}
