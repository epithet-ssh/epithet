// Package eval is SPEC §8 as a pure function: order-independent
// evaluation of a compiled policy against one (user, host, account)
// request. It knows nothing about HTTP, OIDC, or inventories — the
// caller resolves the request tuple and passes resolvers for flags
// (`when`) and facts (`require`).
package eval

import (
	"fmt"
	"slices"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
)

// User is the SCIM-shaped view of a resolved user. ID carries the value
// of the bound identity attribute.
type User struct {
	ID     string
	Active bool
	Groups []string
	Type   string
	Dept   string
	Org    string
}

// Host is a resolved host. Name must already have passed il.HostName.
// Accounts is the grounding list: nil means no account inventory was
// reported and account expressions match the requested name directly
// (ungrounded); non-nil means grounded matching — the requested account
// must be in the list, and an empty list grounds nothing.
type Host struct {
	Name     string
	Labels   map[string]string
	Accounts []string
}

// Request is one evaluation request. A nil User or Host is a structural
// non-match (the SPEC §8 step 1 gates), not an error.
type Request struct {
	User    *User
	Host    *Host
	Account string // requested account name, verbatim — never case-folded
}

// FactState is the three-state result of a `require` fact resolver.
type FactState int

const (
	FactUnknown FactState = iota // unstarted — pends
	FactSatisfied
	FactUnsatisfied
	FactPending
)

// Outcome is the decision category.
type Outcome int

const (
	Deny Outcome = iota
	Issue
	Pending
)

// Decision is the evaluation result. TTL is the minimum across
// satisfied allows that set one; zero means the deployment default.
// DenyRule is set when a deny rule fired; Allowed carries the satisfied
// allows (for notify and audit); PendingOn names the requirements a
// Pending outcome waits on.
type Decision struct {
	Outcome   Outcome
	Reason    string
	TTL       time.Duration
	DenyRule  *il.DenyRule
	Allowed   []*il.AllowRule
	PendingOn []string
}

// FlagFunc resolves a `when` flag: synchronous, two-state, never
// pending. An error fails the evaluation closed.
type FlagFunc func(name string) (bool, error)

// FactFunc resolves a `require` fact through the three-state resolver.
// An error fails the evaluation closed. Request-scoped caching and
// fast-before-side-effecting ordering are the resolver's business.
type FactFunc func(name string) (FactState, error)

// Decide evaluates policy p for req at instant now. It implements SPEC
// §8 steps 1–7; file order never matters. Any resolver error is
// returned as-is — the caller must fail closed (500), never treat it as
// a non-match.
func Decide(p *il.Policy, req Request, now time.Time, flags FlagFunc, facts FactFunc) (Decision, error) {
	// Step 1: structural gates. Not expressible or bypassable in policy.
	if req.User == nil || !req.User.Active {
		return Decision{Outcome: Deny, Reason: "user does not resolve to an active inventory user"}, nil
	}
	if req.Host == nil {
		return Decision{Outcome: Deny, Reason: "host is not in inventory"}, nil
	}
	if req.Host.Accounts != nil && !slices.Contains(req.Host.Accounts, req.Account) {
		return Decision{Outcome: Deny, Reason: fmt.Sprintf("account %q is not in the host's account inventory", req.Account)}, nil
	}

	// Steps 2–4: collect matching rules, deny wins, sync conditions.
	deniedBy, surviving, err := winnowRules(p, req, now, flags)
	if err != nil {
		return Decision{}, err
	}
	if deniedBy != nil {
		return Decision{Outcome: Deny, Reason: "denied by policy rule", DenyRule: deniedBy}, nil
	}

	// Steps 5–7: async requirements.
	return resolveRequirements(surviving, facts)
}

// winnowRules is SPEC §8 steps 2–4: any matching deny whose `when`
// flags currently hold wins outright — no allow can override; matching
// allows whose `when` or `until` conditions fail drop out as
// non-matches, not pending.
//
// Head matching helpers: denyHeadMatches / allowHeadMatches (negation-
// aware). Sync conditions: allFlagsHold for `when`; an allow with
// Until != nil stops matching at that instant. A flag error propagates
// — fail closed.
func winnowRules(p *il.Policy, req Request, now time.Time, flags FlagFunc) (deniedBy *il.DenyRule, surviving []*il.AllowRule, err error) {
	// Every deny is consulted before any allow can succeed: deny-wins
	// holds by construction, not by comparison logic. A deny whose
	// `when` flags do not hold drops out (that loosens, which is why
	// `when` is the only condition a deny may carry).
	for i := range p.Denies {
		d := &p.Denies[i]
		if !denyHeadMatches(d, req) {
			continue
		}
		hold, err := allFlagsHold(d.When, flags)
		if err != nil {
			return nil, nil, err
		}
		if hold {
			return d, nil, nil
		}
	}
	for i := range p.Allows {
		a := &p.Allows[i]
		if !allowHeadMatches(a, req) {
			continue
		}
		// A rule stops matching at its `until` instant; a failed
		// condition here is a non-match, never pending.
		if a.Until != nil && !now.Before(*a.Until) {
			continue
		}
		hold, err := allFlagsHold(a.When, flags)
		if err != nil {
			return nil, nil, err
		}
		if hold {
			surviving = append(surviving, a)
		}
	}
	return nil, surviving, nil
}

// resolveRequirements is SPEC §8 steps 5–7. Any single allow with all
// requirements satisfied issues; else any allow with unstarted or
// pending requirements pends; else deny. An allow with a requirement
// resolved unsatisfied drops out entirely — it neither issues nor
// pends.
func resolveRequirements(surviving []*il.AllowRule, facts FactFunc) (Decision, error) {
	if len(surviving) == 0 {
		return Decision{Outcome: Deny, Reason: "no policy rule allows this access"}, nil
	}
	var satisfied []*il.AllowRule
	var pendingOn []string
	for _, a := range surviving {
		allSat := true
		var pends []string
		for _, name := range a.Require {
			st, err := facts(name)
			if err != nil {
				return Decision{}, fmt.Errorf("resolving requirement %q: %w", name, err)
			}
			switch st {
			case FactSatisfied:
			case FactUnsatisfied:
				allSat = false
				pends = nil
			default: // FactUnknown, FactPending
				allSat = false
				pends = append(pends, name)
			}
			if !allSat && pends == nil {
				break // an unsatisfied fact rules the allow out entirely
			}
		}
		if allSat {
			satisfied = append(satisfied, a)
		} else {
			pendingOn = append(pendingOn, pends...)
		}
	}
	if len(satisfied) > 0 {
		return Decision{Outcome: Issue, TTL: minTTL(satisfied), Allowed: satisfied}, nil
	}
	if len(pendingOn) > 0 {
		slices.Sort(pendingOn)
		return Decision{Outcome: Pending, Reason: "waiting on requirements", PendingOn: slices.Compact(pendingOn)}, nil
	}
	return Decision{Outcome: Deny, Reason: "no allow rule has its requirements satisfied"}, nil
}

// minTTL combines rule TTLs by minimum (SPEC §8): under maximum,
// appending a broad rule would silently lengthen the certs of a
// deliberately tight one. Zero (unset) rules don't participate; zero
// out means the deployment default.
func minTTL(rules []*il.AllowRule) time.Duration {
	var ttl time.Duration
	for _, r := range rules {
		if r.TTL > 0 && (ttl == 0 || r.TTL < ttl) {
			ttl = r.TTL
		}
	}
	return ttl
}

// allFlagsHold reports whether every named `when` flag currently holds.
// A resolver error propagates so the caller fails closed.
func allFlagsHold(names []string, flags FlagFunc) (bool, error) {
	for _, name := range names {
		held, err := flags(name)
		if err != nil {
			return false, fmt.Errorf("resolving flag %q: %w", name, err)
		}
		if !held {
			return false, nil
		}
	}
	return true, nil
}

// ── head matching ───────────────────────────────────────────────────

func allowHeadMatches(a *il.AllowRule, req Request) bool {
	return matchSet(a.Users, userMatcher(req.User)) &&
		matchSet(a.Accounts, accountMatcher(req.Account)) &&
		matchSet(a.Hosts, hostMatcher(req.Host))
}

func denyHeadMatches(d *il.DenyRule, req Request) bool {
	return negSet(d.Users, userMatcher(req.User)) &&
		negSet(d.Accounts, accountMatcher(req.Account)) &&
		negSet(d.Hosts, hostMatcher(req.Host))
}

func matchSet(s il.MatchSet, match func(il.Matcher) bool) bool {
	for _, m := range s.Or {
		if match(m) {
			return true
		}
	}
	return false
}

// negSet applies a deny position's negation bit to the whole set: the
// position matches iff the inner set does not.
func negSet(s il.NegatableMatchSet, match func(il.Matcher) bool) bool {
	matched := matchSet(s.MatchSet, match)
	if s.Not {
		return !matched
	}
	return matched
}

func userMatcher(u *User) func(il.Matcher) bool {
	return func(m il.Matcher) bool {
		switch m.Kind {
		case il.MatchAny:
			return true
		case il.MatchID:
			return m.Value == u.ID
		case il.MatchGroup:
			return slices.Contains(u.Groups, m.Value)
		case il.MatchType:
			return m.Value == u.Type
		case il.MatchDept:
			return m.Value == u.Dept
		case il.MatchOrg:
			return m.Value == u.Org
		}
		return false
	}
}

func accountMatcher(account string) func(il.Matcher) bool {
	return func(m il.Matcher) bool {
		switch m.Kind {
		case il.MatchAny:
			return true
		case il.MatchName:
			return m.Value == account
		case il.MatchGlob:
			return flatGlobMatch(m.Value, account)
		}
		return false
	}
}

func hostMatcher(h *Host) func(il.Matcher) bool {
	return func(m il.Matcher) bool {
		switch m.Kind {
		case il.MatchAny:
			return true
		case il.MatchName:
			return m.Value == h.Name
		case il.MatchGlob:
			return hostpattern.Match(m.Value, h.Name)
		case il.MatchLabels:
			for k, v := range m.Labels {
				if h.Labels[k] != v {
					return false
				}
			}
			return true
		}
		return false
	}
}
