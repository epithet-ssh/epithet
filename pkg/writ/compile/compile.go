// Package compile checks a parsed writ file for well-formedness and
// lowers it to the IL. Checking covers SPEC §7's compile-time rules;
// the apply-time rules (unknown requirement/flag/notify names, past
// until timestamps, inventory-aware lints) belong to whoever owns the
// registries and inventory, not to the language.
package compile

import (
	"fmt"
	"sort"
	"strings"
	"time"

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
	l := &lowerer{macros: map[string][]il.Matcher{}}
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
// duplicate clauses, duplicate selector keys, and the unused-macro and
// duplicate-list-entry lints.
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
	// Duplicates the author wrote lint; duplicates arising from macro
	// expansion are ordinary composition and collapse silently.
	seen := map[string]diag.Pos{}
	for _, atom := range expr.Atoms {
		c.checkAtom(atom, kind)
		key := atomKey(atom)
		if first, ok := seen[key]; ok {
			c.warnf(atom.Pos(), "duplicate list entry — already listed at %s", first)
		} else {
			seen[key] = atom.Pos()
		}
	}
}

func (c *checker) checkAtom(atom ast.Atom, kind ast.Kind) {
	switch a := atom.(type) {
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
	case *ast.Labels:
		seen := map[string]diag.Pos{}
		for _, pair := range a.Pairs {
			if first, ok := seen[pair.Key.Text]; ok {
				c.errf(pair.Key.Pos, "duplicate key `%s` in label selector — first at %s", pair.Key.Text, first)
			} else {
				seen[pair.Key.Text] = pair.Key.Pos
			}
		}
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

// atomKey is a structural key for duplicate detection within one
// authored list.
func atomKey(atom ast.Atom) string {
	switch a := atom.(type) {
	case *ast.MacroRef:
		return "$:" + a.Name
	case *ast.TagMatcher:
		return fmt.Sprintf("t:%s:%s", a.Tag, a.Value.Text)
	case *ast.Name:
		return "n:" + a.Value.Text
	case *ast.Any:
		return "*"
	case *ast.Labels:
		ps := make([]string, 0, len(a.Pairs))
		for _, pair := range a.Pairs {
			ps = append(ps, pair.Key.Text+"="+pair.Value.Text)
		}
		sort.Strings(ps)
		return "l:" + strings.Join(ps, ",")
	}
	return "?"
}

// ── lowering ────────────────────────────────────────────────────────

type lowerer struct {
	macros map[string][]il.Matcher // name → expanded matchers (splices flatten)
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
			l.macros[it.Name] = l.matchers(&it.Body, it.Kind)
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
		Users:    il.MatchSet{Or: l.matchers(&r.Users, ast.KindUser)},
		Accounts: il.MatchSet{Or: l.matchers(&r.Accounts, ast.KindAccount)},
		Hosts:    il.MatchSet{Or: l.matchers(&r.Hosts, ast.KindHost)},
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
		Users:    il.NegatableMatchSet{Not: r.Users.Not, MatchSet: il.MatchSet{Or: l.matchers(&r.Users.Expr, ast.KindUser)}},
		Accounts: il.NegatableMatchSet{Not: r.Accounts.Not, MatchSet: il.MatchSet{Or: l.matchers(&r.Accounts.Expr, ast.KindAccount)}},
		Hosts:    il.NegatableMatchSet{Not: r.Hosts.Not, MatchSet: il.MatchSet{Or: l.matchers(&r.Hosts.Expr, ast.KindHost)}},
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

// matchers lowers an expression to IL matchers, splicing macros. A
// splice flattens: nothing downstream knows the macro existed.
func (l *lowerer) matchers(expr *ast.Expr, kind ast.Kind) []il.Matcher {
	var out []il.Matcher
	for _, atom := range expr.Atoms {
		switch a := atom.(type) {
		case *ast.MacroRef:
			out = append(out, l.macros[a.Name]...)
		case *ast.TagMatcher:
			out = append(out, il.Matcher{Kind: tagKind(a.Tag), Value: a.Value.Text})
		case *ast.Name:
			out = append(out, nameMatcher(a.Value.Text, kind))
		case *ast.Labels:
			labels := make(map[string]string, len(a.Pairs))
			for _, pair := range a.Pairs {
				labels[pair.Key.Text] = pair.Value.Text
			}
			out = append(out, il.Matcher{Kind: il.MatchLabels, Labels: labels})
		case *ast.Any:
			out = append(out, il.Matcher{Kind: il.MatchAny})
		}
	}
	return out
}

// nameMatcher classifies a name as exact or glob. Quoting is a
// rendering decision, not stored state (SPEC §9): a quoted glob in a
// name position globs exactly like a bare one. Host names and globs
// pass through the lowercasing chokepoint here — policy compilation is
// one of the three ingress boundaries.
func nameMatcher(text string, kind ast.Kind) il.Matcher {
	if kind == ast.KindHost {
		text = il.HostName(text)
	}
	if strings.ContainsAny(text, "*?") {
		return il.Matcher{Kind: il.MatchGlob, Value: text}
	}
	return il.Matcher{Kind: il.MatchName, Value: text}
}

func tagKind(t ast.Tag) il.MatcherKind {
	switch t {
	case ast.TagID:
		return il.MatchID
	case ast.TagGroup:
		return il.MatchGroup
	case ast.TagType:
		return il.MatchType
	case ast.TagDept:
		return il.MatchDept
	default:
		return il.MatchOrg
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
