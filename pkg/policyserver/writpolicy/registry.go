// Package writpolicy implements the policy server's PolicyEvaluator
// over a compiled writ policy, an inventory, and registries of
// requirement handlers, flag sources, and notify targets.
//
// The registries are the plugin seam. A name in policy text
// (`require oncall`, `when freeze`, `notify "security-alerts"`) is a
// configured instance bound to that name here; policy referencing an
// unregistered name fails at load, never at request time. The initial
// registry is empty — the subprocess plugin mechanism that will
// populate it is future work, but the contract is fixed now.
package writpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/writ/eval"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
)

// Latency is a requirement handler's declared latency class. Fast
// handlers resolve inline; Human handlers (an approval, a page) are
// triggered only when they are the last thing between the user and a
// cert.
type Latency int

const (
	Fast Latency = iota
	Human
)

// FactStatus is a requirement handler's three-state answer.
type FactStatus int

const (
	Satisfied FactStatus = iota
	Unsatisfied
	Pending
)

// FactResult is one requirement check's outcome. Message surfaces in
// 202 responses ("waiting on approval: https://..."); RetryAfter hints
// the client's next poll; Expires bounds how long a settled answer may
// be cached.
type FactResult struct {
	Status     FactStatus
	Message    string
	RetryAfter time.Duration
	Expires    time.Time
}

// FactRequest is the context a requirement handler judges.
type FactRequest struct {
	Requirement string
	User        eval.User
	Host        eval.Host
	Account     string
	Connection  policy.Connection
	RuleLabel   string
}

// RequirementHandler resolves one named `require` fact. The future
// subprocess implementation (JSON over stdin/stdout, one exec per
// check) implements this interface; latency class and side-effect-ness
// are declared at registration, never in the policy grammar.
type RequirementHandler interface {
	Latency() Latency
	SideEffects() bool
	Check(ctx context.Context, req FactRequest) (FactResult, error)
}

// FlagSource answers `when` flags: synchronous, two-state, never
// pending.
type FlagSource interface {
	Holds(ctx context.Context, name string) (bool, error)
}

// NotifyEvent is a fire-and-forget notification. Event is "issued" or
// "denied"; RuleLabel names the rule that fired (label, or short
// content id when unlabeled).
type NotifyEvent struct {
	Event      string
	Identity   string
	Account    string
	Host       string
	Connection policy.Connection
	RuleLabel  string
}

// Notifier is one registered notify target. Events is the target's
// registered `on` set; Notify must never gate the decision.
type Notifier interface {
	Events() []string
	Notify(ctx context.Context, ev NotifyEvent)
}

// Registry binds the names policy text may reference to their
// configured instances.
type Registry struct {
	Requirements map[string]RequirementHandler
	Flags        map[string]FlagSource
	Notifiers    map[string]Notifier
}

// ValidateReferences checks every require/when/notify name in pol
// against the registry (SPEC §7 apply-time error 14). All unknown
// names are reported at once, each naming the rule that uses it, so an
// operator fixes the whole policy in one pass.
func (r *Registry) ValidateReferences(pol *il.Policy) error {
	var errs []error
	report := func(kind, name, rule string) {
		errs = append(errs, fmt.Errorf("policy references unknown %s %q (rule %s) — no %s with that name is registered", kind, name, rule, kind))
	}
	for i := range pol.Allows {
		a := &pol.Allows[i]
		rule := ruleRef(a.Label, a.ContentID())
		for _, name := range a.Require {
			if _, ok := r.Requirements[name]; !ok {
				report("requirement", name, rule)
			}
		}
		for _, name := range a.When {
			if _, ok := r.Flags[name]; !ok {
				report("flag", name, rule)
			}
		}
		for _, name := range a.Notify {
			if _, ok := r.Notifiers[name]; !ok {
				report("notify target", name, rule)
			}
		}
	}
	for i := range pol.Denies {
		d := &pol.Denies[i]
		rule := ruleRef(d.Label, d.ContentID())
		for _, name := range d.When {
			if _, ok := r.Flags[name]; !ok {
				report("flag", name, rule)
			}
		}
		for _, name := range d.Notify {
			if _, ok := r.Notifiers[name]; !ok {
				report("notify target", name, rule)
			}
		}
	}
	return errors.Join(errs...)
}

// ruleRef is how a rule is named in operator-facing messages: its
// label when it has one, its short content id otherwise.
func ruleRef(label, id string) string {
	if label != "" {
		return fmt.Sprintf("%q", label)
	}
	return il.ShortID(id)
}
