// Package parser turns writ policy source into the AST. The grammar is
// LL(1) at statement start (SPEC §4); this is a hand-written lexer and
// recursive-descent parser because the statement terminator is lexical
// state and the forbidden forms (a negated allow, a headless rule, an
// allow-only clause on a deny, `!` on a list atom) deserve pointed
// diagnostics rather than a generic expectation list.
//
// A statement with errors is reported and dropped; parsing resumes at
// the next statement.
package parser

import (
	"regexp"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/writ/ast"
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
)

var keywords = map[string]bool{
	"allow": true, "deny": true, "user": true, "host": true, "account": true,
	"require": true, "when": true, "until": true, "ttl": true, "notify": true, "label": true,
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:-+[A-Za-z0-9_]+)*$`)

// negCtx is where a match expression sits, for negation diagnostics.
type negCtx int

const (
	ctxAllow negCtx = iota
	ctxDeny
	ctxMacroBody
)

// Parse parses policy source. The returned file holds every statement
// that parsed cleanly; statements with errors are dropped and reported.
func Parse(src string) (*ast.File, []diag.Diagnostic) {
	toks, diags := lex(src)
	p := &parser{toks: toks, diags: diags}
	file := &ast.File{}
	for {
		for p.at(tokTerm) {
			p.advance()
		}
		if p.at(tokEOF) {
			break
		}
		p.bad = false
		if item := p.parseStatement(); item != nil && !p.bad {
			file.Items = append(file.Items, item)
		}
	}
	return file, p.diags
}

type parser struct {
	toks  []token
	i     int
	diags []diag.Diagnostic
	bad   bool // current statement had errors and will be dropped
}

func (p *parser) cur() token        { return p.toks[p.i] }
func (p *parser) at(k tokKind) bool { return p.toks[p.i].kind == k }

func (p *parser) advance() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

func (p *parser) stmtErr(pos diag.Pos, format string, args ...any) {
	p.bad = true
	p.diags = append(p.diags, diag.Errorf(pos, format, args...))
}

// skipToTerm resynchronizes after a hard error: consume through the
// next statement terminator.
func (p *parser) skipToTerm() {
	for !p.at(tokTerm) && !p.at(tokEOF) {
		p.advance()
	}
	if p.at(tokTerm) {
		p.advance()
	}
}

// expectHead consumes the wanted head token or aborts the statement.
func (p *parser) expectHead(k tokKind, want string) bool {
	if p.at(k) {
		p.advance()
		return true
	}
	p.stmtErr(p.cur().pos, "syntax error — expected %s, found %s", want, p.cur().describe())
	p.skipToTerm()
	return false
}

func (p *parser) expectTerm() {
	if p.at(tokTerm) || p.at(tokEOF) {
		if p.at(tokTerm) {
			p.advance()
		}
		return
	}
	p.stmtErr(p.cur().pos, "syntax error — expected end of statement, found %s", p.cur().describe())
	p.skipToTerm()
}

func (p *parser) tagStart() bool {
	t := p.cur()
	return t.kind == tokBare && (t.text == "user" || t.text == "group") && p.toks[p.i+1].kind == tokColon
}

// ── statements ──────────────────────────────────────────────────────

func (p *parser) parseStatement() ast.Item {
	t := p.cur()
	if t.kind == tokBare {
		switch t.text {
		case "user":
			return p.parseMacroDef(ast.KindUser)
		case "host":
			return p.parseMacroDef(ast.KindHost)
		case "account":
			return p.parseMacroDef(ast.KindAccount)
		case "allow":
			return p.parseAllow()
		case "deny":
			return p.parseDeny()
		}
	}
	switch {
	case t.kind == tokBang:
		p.stmtErr(t.pos, "negation is only legal on deny rules — write `deny !...`")
	case t.kind == tokMacroRef || t.kind == tokLBracket ||
		(t.kind == tokBare && t.text == "*") || p.tagStart():
		// The retired headless-rule form gets a migration message.
		p.stmtErr(t.pos, "missing `allow` — rules are `allow <users> -> <accounts>@<hosts>` or `deny ...`")
	default:
		p.stmtErr(t.pos, "syntax error — expected `allow`, `deny`, or a macro definition (`user`, `host`, `account`), found %s", t.describe())
	}
	p.skipToTerm()
	return nil
}

func (p *parser) parseMacroDef(kind ast.Kind) ast.Item {
	kw := p.advance()
	name := p.cur()
	if name.kind != tokBare {
		p.stmtErr(name.pos, "syntax error — expected a macro name, found %s", name.describe())
		p.skipToTerm()
		return nil
	}
	p.advance()
	switch {
	case keywords[name.text]:
		p.stmtErr(name.pos, "`%s` is a keyword and cannot name a macro", name.text)
	case !identRe.MatchString(name.text):
		p.stmtErr(name.pos, "invalid macro name `%s` — identifiers are letters, digits, `_`, and interior `-`", name.text)
	}
	if !p.expectHead(tokEq, "`=`") {
		return nil
	}
	body := p.parseExpr(kind, ctxMacroBody)
	p.expectTerm()
	return &ast.MacroDef{Kind: kind, Name: name.text, Body: body, Pos: kw.pos}
}

func (p *parser) parseAllow() ast.Item {
	kw := p.advance()
	users := p.parseExpr(ast.KindUser, ctxAllow)
	if !p.expectHead(tokArrow, "`->`") {
		return nil
	}
	accounts := p.parseExpr(ast.KindAccount, ctxAllow)
	if !p.expectHead(tokAt, "`@`") {
		return nil
	}
	hosts := p.parseExpr(ast.KindHost, ctxAllow)
	clauses := p.parseClauses(false)
	p.expectTerm()
	return &ast.AllowRule{Users: users, Accounts: accounts, Hosts: hosts, Clauses: clauses, Pos: kw.pos}
}

func (p *parser) parseDeny() ast.Item {
	kw := p.advance()
	notUsers := p.eatBang()
	users := p.parseExpr(ast.KindUser, ctxDeny)
	if !p.expectHead(tokArrow, "`->`") {
		return nil
	}
	notAccounts := p.eatBang()
	accounts := p.parseExpr(ast.KindAccount, ctxDeny)
	if !p.expectHead(tokAt, "`@`") {
		return nil
	}
	notHosts := p.eatBang()
	hosts := p.parseExpr(ast.KindHost, ctxDeny)
	clauses := p.parseClauses(true)
	p.expectTerm()
	return &ast.DenyRule{
		Users:    ast.NegExpr{Not: notUsers, Expr: users},
		Accounts: ast.NegExpr{Not: notAccounts, Expr: accounts},
		Hosts:    ast.NegExpr{Not: notHosts, Expr: hosts},
		Clauses:  clauses,
		Pos:      kw.pos,
	}
}

func (p *parser) eatBang() bool {
	if p.at(tokBang) {
		p.advance()
		return true
	}
	return false
}

// ── match expressions ───────────────────────────────────────────────

func (p *parser) parseExpr(kind ast.Kind, ctx negCtx) ast.Expr {
	pos := p.cur().pos
	return ast.Expr{Atom: p.parseAtom(kind, ctx), Pos: pos}
}

func (p *parser) parseAtom(kind ast.Kind, ctx negCtx) ast.Atom {
	t := p.cur()
	if t.kind == tokBang {
		p.advance()
		if ctx == ctxMacroBody {
			p.stmtErr(t.pos, "negation is not allowed in macro bodies")
		} else {
			p.stmtErr(t.pos, "negation is only legal once, on a whole deny selector")
		}
		p.parseAtom(kind, ctx)
		return nil
	}
	if t.kind == tokLBracket {
		p.stmtErr(t.pos, "selector alternatives are not supported; use separate rules")
		return nil
	}
	if t.kind == tokMacroRef {
		p.advance()
		return &ast.MacroRef{Name: t.text, P: t.pos}
	}
	if kind == ast.KindUser {
		if t.kind == tokBare && t.text == "*" {
			p.advance()
			return &ast.Any{P: t.pos}
		}
		if t.kind != tokBare || (t.text != "user" && t.text != "group") {
			p.stmtErr(t.pos, "expected user or group selector")
			if t.kind != tokEOF && t.kind != tokTerm {
				p.advance()
			}
			return nil
		}
		p.advance()
		if p.at(tokColon) {
			colon := p.advance()
			if colon.start != t.end {
				p.stmtErr(colon.pos, "no space is allowed before the selector colon")
			}
			v := p.parseValue(false)
			if v == nil {
				return nil
			}
			if p.toks[p.i-1].start != colon.end {
				p.stmtErr(v.Pos, "no space is allowed after the selector colon")
			}
			return &ast.Filter{Object: t.text, Pairs: []ast.Pair{{Key: ast.Value{Text: "name", Pos: t.pos}, Value: *v}}, P: t.pos}
		}
		if p.at(tokLBrace) {
			return p.parseFilter(t.text)
		}
		p.stmtErr(p.cur().pos, "expected ':' or '{' after %s", t.text)
		return nil
	}
	if t.kind == tokLBrace {
		f := p.parseFilter("host")
		if kind != ast.KindHost {
			p.stmtErr(t.pos, "object filters are not legal in account position")
		}
		return f
	}
	if t.kind != tokBare && t.kind != tokString {
		p.stmtErr(t.pos, "expected a selector, found %s", t.describe())
		if t.kind != tokEOF && t.kind != tokTerm {
			p.advance()
		}
		return nil
	}
	p.advance()
	if t.kind == tokBare && strings.Contains(t.text, "/") {
		p.stmtErr(t.pos, "'/' is not legal in a bare name; quote the name")
	}
	v := ast.Value{Text: t.text, Quoted: t.kind == tokString, Pos: t.pos}
	if kind == ast.KindAccount {
		if t.text == "*" {
			return &ast.Any{P: t.pos}
		}
		return &ast.Name{Value: v}
	}
	if p.at(tokLBrace) {
		f := p.parseFilter("host")
		if t.text == "*" {
			p.stmtErr(t.pos, "use an attribute-only host filter instead of *{...}")
		}
		f.P = t.pos
		f.Pairs = append([]ast.Pair{{Key: ast.Value{Text: "name", Pos: t.pos}, Value: v}}, f.Pairs...)
		return f
	}
	if t.text == "*" {
		return &ast.Any{P: t.pos}
	}
	return &ast.Filter{Object: "host", Pairs: []ast.Pair{{Key: ast.Value{Text: "name", Pos: t.pos}, Value: v}}, P: t.pos}
}

func (p *parser) parseValue(pattern bool) *ast.Value {
	t := p.cur()
	if t.kind != tokBare && t.kind != tokString {
		p.stmtErr(t.pos, "expected a string value")
		return nil
	}
	p.advance()
	if !pattern && t.kind == tokBare && strings.ContainsAny(t.text, "*?") {
		p.stmtErr(t.pos, "globs are only legal in host/account names; quote a literal wildcard")
	}
	return &ast.Value{Text: t.text, Quoted: t.kind == tokString, Pos: t.pos}
}

func (p *parser) parseFilter(object string) *ast.Filter {
	start := p.advance()
	f := &ast.Filter{Object: object, P: start.pos}
	for !p.at(tokRBrace) {
		if p.at(tokEOF) || p.at(tokTerm) {
			p.stmtErr(p.cur().pos, "unclosed '{'")
			return f
		}
		key := p.parseValue(false)
		if key == nil {
			return f
		}
		if !p.at(tokColon) {
			p.stmtErr(p.cur().pos, "expected ':' in attribute predicate")
			return f
		}
		p.advance()
		value := p.parseValue(object == "host" && key.Text == "name")
		if value == nil {
			return f
		}
		f.Pairs = append(f.Pairs, ast.Pair{Key: *key, Value: *value})
		if p.at(tokComma) {
			p.advance()
			continue
		}
		if !p.at(tokRBrace) {
			p.stmtErr(p.cur().pos, "expected ',' or '}' in filter")
			return f
		}
	}
	p.advance()
	return f
}

func (p *parser) parseClauses(isDeny bool) []ast.Clause {
	var clauses []ast.Clause
	for p.at(tokComma) {
		p.advance()
		kw := p.cur()
		if kw.kind != tokBare {
			p.stmtErr(kw.pos, "syntax error — expected a clause (require, when, until, ttl, notify, label), found %s", kw.describe())
			return clauses
		}
		p.advance()
		switch kw.text {
		case "require":
			names := p.parseNameList()
			if isDeny {
				p.stmtErr(kw.pos, "`require` is not legal on a deny rule — a failed async check must not fail open")
				continue
			}
			clauses = append(clauses, &ast.Require{Names: names, P: kw.pos})
		case "when":
			names := p.parseNameList()
			clauses = append(clauses, &ast.When{Names: names, P: kw.pos})
		case "until":
			s, ok := p.expectValue(tokString, "a quoted timestamp after `until`")
			if !ok {
				continue
			}
			if isDeny {
				p.stmtErr(kw.pos, "`until` is allow-only — a deny that loosens on a schedule needs a human; use a `when` flag")
				continue
			}
			if err := ValidateTimestamp(s.text); err != nil {
				p.stmtErr(s.pos, "%s", err)
				continue
			}
			clauses = append(clauses, &ast.Until{TS: ast.Value{Text: s.text, Quoted: true, Pos: s.pos}, P: kw.pos})
		case "ttl":
			b, ok := p.expectValue(tokBare, "a duration after `ttl`")
			if !ok {
				continue
			}
			if isDeny {
				p.stmtErr(kw.pos, "`ttl` is allow-only — a deny issues nothing")
				continue
			}
			secs, err := ParseDuration(b.text)
			if err != nil {
				p.stmtErr(b.pos, "%s", err)
				continue
			}
			clauses = append(clauses, &ast.TTL{Seconds: secs, P: kw.pos})
		case "notify":
			targets := p.parseStringList()
			clauses = append(clauses, &ast.Notify{Targets: targets, P: kw.pos})
		case "label":
			s, ok := p.expectValue(tokString, "a quoted string after `label`")
			if !ok {
				continue
			}
			clauses = append(clauses, &ast.Label{Value: ast.Value{Text: s.text, Quoted: true, Pos: s.pos}, P: kw.pos})
		default:
			p.stmtErr(kw.pos, "unknown clause `%s` — expected require, when, until, ttl, notify, or label", kw.text)
		}
	}
	return clauses
}

// expectValue consumes a clause value of the wanted kind, or reports
// without consuming so the clause loop can resynchronize.
func (p *parser) expectValue(k tokKind, want string) (token, bool) {
	if p.at(k) {
		return p.advance(), true
	}
	p.stmtErr(p.cur().pos, "syntax error — expected %s, found %s", want, p.cur().describe())
	return token{}, false
}

func (p *parser) parseNameList() []ast.Value {
	return p.parseValueList(func() (ast.Value, bool) {
		t := p.cur()
		if t.kind != tokBare && t.kind != tokString {
			p.stmtErr(t.pos, "syntax error — expected a name, found %s", t.describe())
			return ast.Value{}, false
		}
		p.advance()
		return ast.Value{Text: t.text, Quoted: t.kind == tokString, Pos: t.pos}, true
	})
}

func (p *parser) parseStringList() []ast.Value {
	return p.parseValueList(func() (ast.Value, bool) {
		t := p.cur()
		if t.kind != tokString {
			p.stmtErr(t.pos, "syntax error — expected a quoted string, found %s", t.describe())
			return ast.Value{}, false
		}
		p.advance()
		return ast.Value{Text: t.text, Quoted: true, Pos: t.pos}, true
	})
}

func (p *parser) parseValueList(item func() (ast.Value, bool)) []ast.Value {
	var vals []ast.Value
	if !p.at(tokLBracket) {
		if v, ok := item(); ok {
			vals = append(vals, v)
		}
		return vals
	}
	p.advance()
	for {
		if p.at(tokRBracket) {
			p.advance()
			break
		}
		if p.at(tokTerm) || p.at(tokEOF) {
			p.stmtErr(p.cur().pos, "syntax error — unclosed `[`")
			break
		}
		v, ok := item()
		if ok {
			vals = append(vals, v)
		} else {
			p.advance()
		}
		if p.at(tokComma) {
			p.advance()
			continue
		}
		if !p.at(tokRBracket) {
			p.stmtErr(p.cur().pos, "syntax error — expected `,` or `]`, found %s", p.cur().describe())
			break
		}
	}
	return vals
}
