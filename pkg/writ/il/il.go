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
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
)

// Schema is the IL schema version carried by every policy.
const Schema = 2

// Policy is a compiled rule set. Rule order is preserved from the
// source for reporting, but evaluation is order-independent.
type Policy struct {
	Schema int
	Allows []AllowRule
	Denies []DenyRule
}

// ValidateUserSelectors rejects incompatible IL before any rule can grant
// access. In particular, ignoring a legacy matcher in a deny would fail open.
func (p *Policy) ValidateUserSelectors() error {
	if p == nil {
		return fmt.Errorf("nil Writ policy")
	}
	if p.Schema != Schema {
		return fmt.Errorf("unsupported Writ IL schema %d (want %d); migrate legacy name selectors to userName: and recompile the policy", p.Schema, Schema)
	}
	check := func(users MatchSet) error {
		for _, m := range users.Or {
			switch m.Kind {
			case MatchUserName, MatchID, MatchGroup, MatchUserType, MatchDepartment, MatchOrganization, MatchAny:
			default:
				return fmt.Errorf("unsupported Writ user matcher %q; use user selectors: userName, id, group, userType, department, organization", m.Kind)
			}
		}
		return nil
	}
	for _, a := range p.Allows {
		if err := check(a.Users); err != nil {
			return err
		}
	}
	for _, d := range p.Denies {
		if err := check(d.Users.MatchSet); err != nil {
			return err
		}
	}
	return nil
}

// MatcherKind discriminates Matcher values.
type MatcherKind string

const (
	// User position.
	MatchUserName     MatcherKind = "userName"
	MatchID           MatcherKind = "id"
	MatchGroup        MatcherKind = "group"
	MatchUserType     MatcherKind = "userType"
	MatchDepartment   MatcherKind = "department"
	MatchOrganization MatcherKind = "organization"
	// Account and host positions.
	MatchName MatcherKind = "name"
	MatchGlob MatcherKind = "glob"
	// Host position only.
	MatchLabels MatcherKind = "labels"
	// Every position. A surface `*` compiles to MatchAny, never to a
	// glob — it is semantically distinct and skips the glob engine.
	MatchAny MatcherKind = "any"
)

// Matcher is one matcher. Value carries the scalar for every kind but
// MatchLabels and MatchAny; host name/glob values are stored
// ASCII-lowercased. Labels is set only for MatchLabels; entries AND.
type Matcher struct {
	Kind   MatcherKind
	Value  string
	Labels map[string]string
}

// MatchSet is a disjunction of matchers (an allow-rule position).
type MatchSet struct {
	Or []Matcher
}

// NegatableMatchSet is a match set plus a negation bit (a deny-rule
// position). Not applies to the whole set: the position matches iff the
// inner set does not.
type NegatableMatchSet struct {
	Not bool
	MatchSet
}

// AllowRule grants access when all three positions match and every
// clause holds. Label is cosmetic and excluded from the content id.
// Until nil means no expiry; TTL zero means the deployment default.
type AllowRule struct {
	Label    string
	Users    MatchSet
	Accounts MatchSet
	Hosts    MatchSet
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
	Users    NegatableMatchSet
	Accounts NegatableMatchSet
	Hosts    NegatableMatchSet
	When     []string
	Notify   []string
}

// HostName is the single chokepoint for host-name normalization
// (SPEC §12 q9): ASCII A-Z→a-z only, never Unicode folding. Apply it at
// every ingress boundary — inventory load, request resolution, and
// policy compilation — so matching stays a byte compare.
func HostName(s string) string { return hostpattern.NormalizeName(s) }
