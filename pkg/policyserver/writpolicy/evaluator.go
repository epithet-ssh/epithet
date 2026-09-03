package writpolicy

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/inventory"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ/eval"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
)

// Options carries the deployment-level certificate parameters. Writ
// controls TTL only; extensions are deployment config by design.
type Options struct {
	// DefaultTTL is the cert expiration when no satisfied rule sets a
	// ttl. Zero falls back to policyserver.DefaultExpiration().
	DefaultTTL time.Duration
	// Extensions go into every issued cert. Nil falls back to
	// policyserver.DefaultExtensions().
	Extensions map[string]string
	// Clock is the evaluation time source; nil means time.Now.
	Clock func() time.Time
}

// Evaluator implements policyserver.PolicyEvaluator over a compiled
// writ policy. The policy is immutable after construction — reload is
// a process restart.
type Evaluator struct {
	pol  *il.Policy
	inv  inventory.Inventory
	reg  *Registry
	opts Options
}

// New builds an evaluator, validating every require/when/notify
// reference against the registry (unknown names fail here, at startup)
// and collecting non-blocking warnings: an allow whose `until` is
// already past matches nothing, which is safe, so it warns rather than
// bricking a restart.
func New(pol *il.Policy, inv inventory.Inventory, reg *Registry, opts Options) (*Evaluator, []string, error) {
	if reg == nil {
		reg = &Registry{}
	}
	if err := reg.ValidateReferences(pol); err != nil {
		return nil, nil, err
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.DefaultTTL == 0 {
		d, err := time.ParseDuration(policyserver.DefaultExpiration())
		if err != nil {
			return nil, nil, fmt.Errorf("parsing default expiration: %w", err)
		}
		opts.DefaultTTL = d
	}
	if opts.Extensions == nil {
		opts.Extensions = policyserver.DefaultExtensions()
	}
	var warnings []string
	now := opts.Clock()
	for i := range pol.Allows {
		a := &pol.Allows[i]
		if a.Until != nil && !now.Before(*a.Until) {
			warnings = append(warnings, fmt.Sprintf("rule %s has an `until` in the past (%s) and can never match",
				ruleRef(a.Label, a.ContentID()), a.Until.UTC().Format(time.RFC3339)))
		}
	}
	return &Evaluator{pol: pol, inv: inv, reg: reg, opts: opts}, warnings, nil
}

// NewForTesting builds an evaluator with an empty registry and default
// options, panicking on validation failure. Tests only.
func NewForTesting(pol *il.Policy, inv inventory.Inventory) *Evaluator {
	e, _, err := New(pol, inv, &Registry{}, Options{})
	if err != nil {
		panic(err)
	}
	return e
}

// Evaluate implements policyserver.PolicyEvaluator: resolve the request
// tuple through the inventory, run the writ evaluation, and map the
// decision onto the wire. Inventory and resolver failures return plain
// errors (500, fail closed); policy denials return 403; pending
// requirements return 202.
func (e *Evaluator) Evaluate(ctx context.Context, identity string, tokenExpiry time.Time, conn policy.Connection) (*wire.PolicyResponse, error) {
	user, err := e.inv.LookupUser(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}
	hostName := il.HostName(conn.RemoteHost)
	host, err := e.inv.LookupHost(ctx, hostName)
	if err != nil {
		return nil, fmt.Errorf("looking up host: %w", err)
	}

	var policyHost *eval.Host
	if host != nil {
		policyHost = &host.Policy
	}
	req := eval.Request{User: user, Host: policyHost, Account: conn.RemoteUser}
	decision, err := eval.Decide(e.pol, req, e.opts.Clock(),
		e.flagResolver(ctx),
		e.factResolver(ctx, req, conn))
	if err != nil {
		return nil, err
	}

	switch decision.Outcome {
	case eval.Issue:
		e.notify(ctx, "issued", identity, conn, issuedLabels(decision.Allowed))
		ttl := decision.TTL
		if ttl == 0 {
			ttl = e.opts.DefaultTTL
		}
		return &wire.PolicyResponse{
			CertParams: wire.CertParams{
				Identity: identity,
				// Compatibility profile: this account-name principal is not
				// destination-bound. Enterprise will derive a principal from the
				// enrolled host identity key and requested account name.
				Names:      []string{conn.RemoteUser},
				Expiration: ttl,
				Extensions: e.opts.Extensions,
				NotAfter:   tokenExpiry,
			},
		}, nil
	case eval.Pending:
		return nil, &wire.PolicyError{
			StatusCode: http.StatusAccepted,
			Message:    "certificate not yet issuable — waiting on: " + strings.Join(decision.PendingOn, ", "),
		}
	default:
		detail := decision.Reason
		if decision.DenyRule != nil {
			detail = fmt.Sprintf("denied by rule %s", ruleRef(decision.DenyRule.Label, decision.DenyRule.ContentID()))
			e.notifyDeny(ctx, identity, conn, decision.DenyRule)
		}
		return nil, policyserver.Forbidden(fmt.Sprintf("%s is not authorized for %s@%s: %s",
			identity, conn.RemoteUser, conn.RemoteHost, detail))
	}
}

func (e *Evaluator) flagResolver(ctx context.Context) eval.FlagFunc {
	return func(name string) (bool, error) {
		src, ok := e.reg.Flags[name]
		if !ok {
			// Unreachable after ValidateReferences; fail closed anyway.
			return false, fmt.Errorf("no flag source registered for %q", name)
		}
		return src.Holds(ctx, name)
	}
}

func (e *Evaluator) factResolver(ctx context.Context, req eval.Request, conn policy.Connection) eval.FactFunc {
	// Request-scoped memoization: several allows naming the same fact
	// resolve it once.
	cache := map[string]eval.FactState{}
	return func(name string) (eval.FactState, error) {
		if st, ok := cache[name]; ok {
			return st, nil
		}
		handler, ok := e.reg.Requirements[name]
		if !ok {
			return eval.FactUnknown, fmt.Errorf("no requirement handler registered for %q", name)
		}
		res, err := handler.Check(ctx, FactRequest{
			Requirement: name,
			User:        *req.User,
			Host:        *req.Host,
			Account:     req.Account,
			Connection:  conn,
		})
		if err != nil {
			return eval.FactUnknown, err
		}
		var st eval.FactState
		switch res.Status {
		case Satisfied:
			st = eval.FactSatisfied
		case Unsatisfied:
			st = eval.FactUnsatisfied
		default:
			st = eval.FactPending
		}
		cache[name] = st
		return st, nil
	}
}

// notify fires the registered targets for the rules that fired. It is
// fire-and-forget by contract: dispatch happens on a detached context
// and never affects the decision.
func (e *Evaluator) notify(ctx context.Context, event, identity string, conn policy.Connection, byTarget map[string]string) {
	for target, ruleLabel := range byTarget {
		n, ok := e.reg.Notifiers[target]
		if !ok || !slices.Contains(n.Events(), event) {
			continue
		}
		ev := NotifyEvent{
			Event:      event,
			Identity:   identity,
			Account:    conn.RemoteUser,
			Host:       conn.RemoteHost,
			Connection: conn,
			RuleLabel:  ruleLabel,
		}
		go n.Notify(context.WithoutCancel(ctx), ev)
	}
}

func (e *Evaluator) notifyDeny(ctx context.Context, identity string, conn policy.Connection, d *il.DenyRule) {
	targets := map[string]string{}
	for _, t := range d.Notify {
		targets[t] = ruleRef(d.Label, d.ContentID())
	}
	e.notify(ctx, "denied", identity, conn, targets)
}

func issuedLabels(allowed []*il.AllowRule) map[string]string {
	targets := map[string]string{}
	for _, a := range allowed {
		for _, t := range a.Notify {
			targets[t] = ruleRef(a.Label, a.ContentID())
		}
	}
	return targets
}
