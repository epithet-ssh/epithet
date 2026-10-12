// Package compile checks a parsed writ file for well-formedness and
// lowers it to the IL. Checking covers SPEC §7's compile-time rules;
// the apply-time rules (unknown requirement/flag/notify names, past
// until timestamps, inventory-aware lints) belong to whoever owns the
// registries and inventory, not to the language.
package compile

import (
	"fmt"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/writ/ast"
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
)

// Compile checks file and lowers it to a policy. The policy is non-nil
// iff no error-severity diagnostics were produced; warnings never
// block.
func Compile(file *ast.File) (*il.Policy, []diag.Diagnostic) {
	diags := Check(file)
	if diag.HasErrors(diags) {
		return nil, diags
	}
	l := &lowerer{macros: map[string]il.Selector{}}
	pol := l.lower(file)
	diags = append(diags, l.diags...)
	// Lowering itself can error (e.g. a timestamp the shape validator
	// admits but the calendar rejects); a policy with a dropped clause
	// is broader than authored, so it must not be returned.
	if diag.HasErrors(diags) {
		return nil, diags
	}
	return pol, diags
}

// ── well-formedness ─────────────────────────────────────────────────

// Check runs the compile-time static checks on a parsed file: macro
// resolution (define-before-use, redefinition, kind mismatch),
// duplicate clauses, and unused macros.
func Check(file *ast.File) []diag.Diagnostic {
	c := &checker{macros: map[string]*macroInfo{}}
	c.run(file)
	return c.diags
}

type macroInfo struct {
	kind ast.Kind
	pos  diag.Pos
	used bool
	name string
}

type checker struct {
	macros map[string]*macroInfo
	order  []*macroInfo
	diags  []diag.Diagnostic
}

func (c *checker) errf(pos diag.Pos, format string, args ...any) {
	c.diags = append(c.diags, diag.Errorf(pos, format, args...))
}

func (c *checker) warnf(pos diag.Pos, format string, args ...any) {
	c.diags = append(c.diags, diag.Warnf(pos, format, args...))
}

func (c *checker) run(file *ast.File) {
	for _, item := range file.Items {
		switch it := item.(type) {
		case *ast.MacroDef:
			// The body resolves against macros defined so far:
			// define-before-use makes cycles (and self-reference)
			// impossible by construction.
			c.checkExpr(&it.Body, it.Kind)
			if prev, ok := c.macros[it.Name]; ok {
				c.errf(it.Pos, "macro `%s` redefined — first defined at %s", it.Name, prev.pos)
			} else {
				info := &macroInfo{kind: it.Kind, pos: it.Pos, name: it.Name}
				c.macros[it.Name] = info
				c.order = append(c.order, info)
			}
		case *ast.AllowRule:
			c.checkExpr(&it.Users, ast.KindUser)
			c.checkExpr(&it.Accounts, ast.KindAccount)
			c.checkExpr(&it.Hosts, ast.KindHost)
			c.checkClauses(it.Clauses)
		case *ast.DenyRule:
			c.checkExpr(&it.Users.Expr, ast.KindUser)
			c.checkExpr(&it.Accounts.Expr, ast.KindAccount)
			c.checkExpr(&it.Hosts.Expr, ast.KindHost)
			c.checkClauses(it.Clauses)
		}
	}
	for _, info := range c.order {
		if !info.used {
			c.warnf(info.pos, "macro `%s` is defined but never referenced", info.name)
		}
	}
}

func (c *checker) checkExpr(expr *ast.Expr, kind ast.Kind) {
	switch a := expr.Atom.(type) {
	case *ast.MacroRef:
		info, ok := c.macros[a.Name]
		if !ok {
			c.errf(a.P, "macro `$%s` referenced before definition", a.Name)
			return
		}
		info.used = true
		if info.kind != kind {
			c.errf(a.P, "`$%s` is a %s macro, used in %s position", a.Name, info.kind, kind)
		}
	case *ast.Filter:
		for _, p := range a.Pairs {
			if a.Object == "host" && p.Key.Text == "name" && strings.ContainsAny(p.Value.Text, "*?") {
				if _, err := hostpattern.Parse(il.HostName(p.Value.Text)); err != nil {
					c.errf(p.Value.Pos, "invalid host pattern `%s`: %v", p.Value.Text, err)
				}
			}
		}
	case *ast.Name, *ast.Any:
	default:
		c.errf(expr.Pos, "missing selector")
	}
}

func (c *checker) checkClauses(clauses []ast.Clause) {
	seen := map[string]diag.Pos{}
	for _, cl := range clauses {
		if first, ok := seen[cl.Keyword()]; ok {
			c.errf(cl.Pos(), "duplicate `%s` clause — first at %s; combine into one list", cl.Keyword(), first)
		} else {
			seen[cl.Keyword()] = cl.Pos()
		}
	}
}

// ── lowering ────────────────────────────────────────────────────────

type lowerer struct {
	macros map[string]il.Selector // name → fully expanded selector
	diags  []diag.Diagnostic
}

type ruleID struct {
	pos   diag.Pos
	label string
}

func (l *lowerer) lower(file *ast.File) *il.Policy {
	pol := &il.Policy{Schema: il.Schema}
	// Duplicate content ids warn and collapse, keeping the first label
	// (SPEC §11): labels are cosmetic, so the collapse loses nothing.
	seen := map[string]ruleID{}
	for _, item := range file.Items {
		switch it := item.(type) {
		case *ast.MacroDef:
			l.macros[it.Name] = l.selector(&it.Body, it.Kind)
		case *ast.AllowRule:
			rule := l.lowerAllow(it)
			if first, ok := seen[rule.ContentID()]; ok {
				l.dupWarn(it.Pos, first)
				continue
			}
			seen[rule.ContentID()] = ruleID{pos: it.Pos, label: rule.Label}
			pol.Allows = append(pol.Allows, rule)
		case *ast.DenyRule:
			rule := l.lowerDeny(it)
			if first, ok := seen[rule.ContentID()]; ok {
				l.dupWarn(it.Pos, first)
				continue
			}
			seen[rule.ContentID()] = ruleID{pos: it.Pos, label: rule.Label}
			pol.Denies = append(pol.Denies, rule)
		}
	}
	return pol
}

func (l *lowerer) dupWarn(pos diag.Pos, first ruleID) {
	l.diags = append(l.diags, diag.Warnf(pos,
		"rule is identical to the rule at %s (same content id) — the two collapse to one", first.pos))
}

func (l *lowerer) lowerAllow(r *ast.AllowRule) il.AllowRule {
	rule := il.AllowRule{
		Users:    l.selector(&r.Users, ast.KindUser),
		Accounts: l.selector(&r.Accounts, ast.KindAccount),
		Hosts:    l.selector(&r.Hosts, ast.KindHost),
	}
	for _, cl := range r.Clauses {
		switch c := cl.(type) {
		case *ast.Require:
			rule.Require = valueTexts(c.Names)
		case *ast.When:
			rule.When = valueTexts(c.Names)
		case *ast.Until:
			ts, err := parseTimestamp(c.TS.Text)
			if err != nil {
				// The parser validated the shape; only exotic values
				// (e.g. a :60 leap second) reach here.
				l.diags = append(l.diags, diag.Errorf(c.TS.Pos, "invalid timestamp `%s`", c.TS.Text))
				continue
			}
			rule.Until = &ts
		case *ast.TTL:
			rule.TTL = time.Duration(c.Seconds) * time.Second
		case *ast.Notify:
			rule.Notify = valueTexts(c.Targets)
		case *ast.Label:
			rule.Label = c.Value.Text
		}
	}
	return rule
}

func (l *lowerer) lowerDeny(r *ast.DenyRule) il.DenyRule {
	rule := il.DenyRule{
		Users:    il.NegatableSelector{Not: r.Users.Not, Selector: l.selector(&r.Users.Expr, ast.KindUser)},
		Accounts: il.NegatableSelector{Not: r.Accounts.Not, Selector: l.selector(&r.Accounts.Expr, ast.KindAccount)},
		Hosts:    il.NegatableSelector{Not: r.Hosts.Not, Selector: l.selector(&r.Hosts.Expr, ast.KindHost)},
	}
	for _, cl := range r.Clauses {
		switch c := cl.(type) {
		case *ast.When:
			rule.When = valueTexts(c.Names)
		case *ast.Notify:
			rule.Notify = valueTexts(c.Targets)
		case *ast.Label:
			rule.Label = c.Value.Text
		}
	}
	return rule
}

// selector expands aliases and preserves every predicate in the conjunction.
// Canonical identity ignores ordering and identical repetitions.
func (l *lowerer) selector(expr *ast.Expr, kind ast.Kind) il.Selector {
	switch a := expr.Atom.(type) {
	case *ast.MacroRef:
		return l.macros[a.Name]
	case *ast.Filter:
		s := il.Selector{Kind: il.Kind(a.Object)}
		for _, p := range a.Pairs {
			value := p.Value.Text
			if a.Object == "host" && p.Key.Text == "name" {
				value = il.HostName(value)
			}
			s.Predicates = append(s.Predicates, il.Predicate{Attribute: p.Key.Text, Value: value})
		}
		return s
	case *ast.Name:
		return il.Selector{Kind: il.Account, Predicates: []il.Predicate{{Attribute: "name", Value: a.Value.Text}}}
	default:
		return il.Selector{Kind: il.Kind(kind.String())}
	}
}

func valueTexts(vals []ast.Value) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = v.Text
	}
	return out
}

// parseTimestamp parses the already shape-validated RFC 3339 timestamp
// forms: seconds optional, fraction optional, `t`/space date-time
// separators, `z` offset.
func parseTimestamp(s string) (time.Time, error) {
	if len(s) > 10 && (s[10] == 't' || s[10] == ' ') {
		s = s[:10] + "T" + s[11:]
	}
	if s[len(s)-1] == 'z' {
		s = s[:len(s)-1] + "Z"
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02T15:04Z07:00",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable timestamp %q", s)
}
