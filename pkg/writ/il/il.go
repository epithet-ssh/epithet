// Package il is writ's intermediate language: the compiled rule format
// per SPEC §10–11. The IL is writ's real policy interface; the surface
// language is one frontend over it. Macros are fully expanded here —
// nothing downstream of the compiler knows they existed.
//
// IL equality is canonical, not structural: two rules are the same rule
// iff their content ids match. Nothing may compare rules with deep
// equality.
package il

import (
	"fmt"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
)

// Schema is the IL schema version carried by every policy.
const Schema = 3

// Policy is a compiled rule set. Rule order is preserved from the
// source for reporting, but evaluation is order-independent.
type Policy struct {
	Schema int
	Allows []AllowRule
	Denies []DenyRule
}

// Validate rejects unsupported schemas, kinds, positions, and malformed
// selectors before any rule (including a deny) can be evaluated.
func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("nil Writ policy")
	}
	if p.Schema != Schema {
		return fmt.Errorf("unsupported Writ IL schema %d (want %d); recompile the policy", p.Schema, Schema)
	}
	check := func(s Selector, position string) error {
		switch position {
		case "user":
			if s.Kind != User && s.Kind != Group {
				return fmt.Errorf("invalid user selector kind %q", s.Kind)
			}
		case "host":
			if s.Kind != Host {
				return fmt.Errorf("invalid host selector kind %q", s.Kind)
			}
		case "account":
			if s.Kind != Account {
				return fmt.Errorf("invalid account selector kind %q", s.Kind)
			}
		}
		for _, pred := range s.Predicates {
			if position == "account" && pred.Attribute != "name" {
				return fmt.Errorf("accounts support only name matching")
			}
			if pred.Attribute == "name" && s.Kind == Host {
				if pred.Value != HostName(pred.Value) {
					return fmt.Errorf("host predicate is not normalized")
				}
				if _, err := hostpattern.Parse(pred.Value); strings.ContainsAny(pred.Value, "*?") && err != nil {
					return fmt.Errorf("invalid host name predicate: %w", err)
				}
			}
		}
		if position == "account" && len(s.Predicates) > 1 {
			return fmt.Errorf("account selector must contain at most one name predicate")
		}
		return nil
	}
	for _, r := range p.Allows {
		for _, s := range []struct {
			s Selector
			p string
		}{{r.Users, "user"}, {r.Accounts, "account"}, {r.Hosts, "host"}} {
			if err := check(s.s, s.p); err != nil {
				return err
			}
		}
	}
	for _, r := range p.Denies {
		for _, s := range []struct {
			s Selector
			p string
		}{{r.Users.Selector, "user"}, {r.Accounts.Selector, "account"}, {r.Hosts.Selector, "host"}} {
			if err := check(s.s, s.p); err != nil {
				return err
			}
		}
	}
	return nil
}

// Kind identifies the object selected at one rule position.
type Kind string

const (
	User    Kind = "user"
	Group   Kind = "group"
	Host    Kind = "host"
	Account Kind = "account"
)

// Predicate requires one string value. Repeated attributes remain separate
// conjuncts, so a map cannot represent a filter. Host/account name predicates
// use their established name-pattern languages; all other comparisons are exact.
type Predicate struct {
	Attribute string
	Value     string
}

// Selector matches one object satisfying every predicate. An empty predicate
// list accepts every candidate; a group selector still requires a membership.
// There is no representation for selector alternatives.
type Selector struct {
	Kind       Kind
	Predicates []Predicate
}

// NegatableSelector is available only in deny rules. Not complements the whole
// selector, after matching all candidate names or memberships.
type NegatableSelector struct {
	Not bool
	Selector
}

// AllowRule grants access when all three positions match and every
// clause holds. Label is cosmetic and excluded from the content id.
// Until nil means no expiry; TTL zero means the deployment default.
type AllowRule struct {
	Label    string
	Users    Selector
	Accounts Selector
	Hosts    Selector
	Require  []string
	When     []string
	Until    *time.Time
	TTL      time.Duration
	Notify   []string
}

// DenyRule withdraws access when all three positions match and its
// `when` flags (if any) hold. Deny always wins.
type DenyRule struct {
	Label    string
	Users    NegatableSelector
	Accounts NegatableSelector
	Hosts    NegatableSelector
	When     []string
	Notify   []string
}

// HostName is the single chokepoint for host-name normalization
// (SPEC §12 q9): ASCII A-Z→a-z only, never Unicode folding. Apply it at
// every ingress boundary — inventory load, request resolution, and
// policy compilation — so matching stays a byte compare.
func HostName(s string) string { return hostpattern.NormalizeName(s) }
