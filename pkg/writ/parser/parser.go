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

func (p *parser) cur() token  { return p.toks[p.i] }
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

// tagStart reports whether the parser sits on `tag:` — a tag word with
// an immediately adjacent colon (no interior whitespace, SPEC §3).
func (p *parser) tagStart() bool {
	t := p.cur()
	if t.kind != tokBare {
		return false
	}
	if _, ok := ast.TagOf(t.text); !ok {
		return false
	}
	n := p.toks[p.i+1]
	return n.kind == tokColon && n.start == t.end
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
	if !p.at(tokLBracket) {
		var atoms []ast.Atom
		if a := p.parseAtom(kind, ctx, false); a != nil {
			atoms = append(atoms, a)
		}
		return ast.Expr{Atoms: atoms, Pos: pos}
	}
	p.advance()
	var atoms []ast.Atom
	for {
		if p.at(tokRBracket) {
			p.advance()
			break
		}
		if p.at(tokTerm) || p.at(tokEOF) {
			p.stmtErr(p.cur().pos, "syntax error — unclosed `[`")
			break
		}
		if a := p.parseAtom(kind, ctx, true); a != nil {
			atoms = append(atoms, a)
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
	if len(atoms) == 0 && !p.bad {
		p.stmtErr(pos, "syntax error — expected at least one matcher in the list")
	}
	return ast.Expr{Atoms: atoms, Bracketed: true, Pos: pos}
}

func (p *parser) parseAtom(kind ast.Kind, ctx negCtx, inList bool) ast.Atom {
	t := p.cur()
	switch t.kind {
	case tokBang:
		p.advance()
		var msg string
		switch {
		case ctx == ctxMacroBody:
			msg = "negation is not allowed in macro bodies — macros are purely positive"
		case ctx == ctxAllow:
			msg = "negation is only legal on deny rules"
		case inList:
			msg = "negation applies to the whole expression — write `![$a, $b]`, not `[!$a, !$b]`"
		default:
			msg = "unexpected `!` — negation already applies to the whole expression"
		}
		p.stmtErr(t.pos, "%s", msg)
		p.parseAtom(kind, ctx, inList) // consume the negated atom
		return nil
	case tokMacroRef:
		p.advance()
		return &ast.MacroRef{Name: t.text, P: t.pos}
	case tokString:
		p.advance()
		if kind == ast.KindUser {
			p.stmtErr(t.pos, "a quoted string alone is not a user matcher — use `id:\"...\"`, `group:\"...\"`, etc.")
			return nil
		}
		return &ast.Name{Value: ast.Value{Text: t.text, Quoted: true, Pos: t.pos}}
	case tokLBrace:
		sel := p.parseLabelSel()
		if kind != ast.KindHost {
			p.stmtErr(t.pos, "a `{key=value}` selector is only legal in host position")
			return nil
		}
		return sel
	case tokBare:
		if kind == ast.KindUser {
			return p.parseUserBare(t)
		}
		p.advance()
		if t.text == "*" {
			return &ast.Any{P: t.pos}
		}
		if strings.Contains(t.text, "/") {
			p.stmtErr(t.pos, "`/` is not legal in a bare name — quote \"%s\" if the name really contains `/`", t.text)
			return nil
		}
		return &ast.Name{Value: ast.Value{Text: t.text, Quoted: false, Pos: t.pos}}
	default:
		p.stmtErr(t.pos, "syntax error — expected a matcher, found %s", t.describe())
		if t.kind != tokTerm && t.kind != tokEOF {
			p.advance()
		}
		return nil
	}
}

func (p *parser) parseUserBare(t token) ast.Atom {
	if tag, ok := ast.TagOf(t.text); ok && p.tagStart() {
		p.advance()             // tag word
		colon := p.advance()    // adjacent colon
		val := p.parseAttrValue(t.text+":", &colon)
		if val == nil {
			return nil
		}
		return &ast.TagMatcher{Tag: tag, Value: *val}
	}
	p.advance()
	if t.text == "*" {
		return &ast.Any{P: t.pos}
	}
	if _, ok := ast.TagOf(t.text); ok {
		p.stmtErr(t.pos, "expected `:` after user tag `%s`", t.text)
	} else {
		p.stmtErr(t.pos, "bare words are not user matchers — identity is opaque; use `id:\"%s\"` or a tag matcher (id, group, type, dept, org)", t.text)
	}
	return nil
}

// parseAttrValue parses an attribute value (after `tag:` or `key=`).
// Globs match names, never attribute values (SPEC §7 error 11); a
// quoted value is always a literal. A non-nil after token enforces
// adjacency (tag values allow no interior whitespace).
func (p *parser) parseAttrValue(ctxStr string, after *token) *ast.Value {
	v := p.cur()
	if v.kind != tokBare && v.kind != tokString {
		p.stmtErr(v.pos, "syntax error — expected a value after `%s`, found %s", ctxStr, v.describe())
		return nil
	}
	if after != nil && v.start != after.end {
		p.stmtErr(v.pos, "no space is allowed in `%svalue`", ctxStr)
		return nil
	}
	p.advance()
	if v.kind == tokBare && strings.ContainsAny(v.text, "*?") {
		p.stmtErr(v.pos, "globs match names, never attribute values — quote the value (`%s\"%s\"`) to match a literal, or use a union of exact values", ctxStr, v.text)
		return nil
	}
	return &ast.Value{Text: v.text, Quoted: v.kind == tokString, Pos: v.pos}
}

func (p *parser) parseLabelSel() *ast.Labels {
	lb := p.advance() // {
	var pairs []ast.LabelPair
	for {
		if p.at(tokRBrace) {
			p.advance()
			break
		}
		if p.at(tokTerm) || p.at(tokEOF) {
			p.stmtErr(p.cur().pos, "syntax error — unclosed `{`")
			break
		}
		kt := p.cur()
		var key *ast.Value
		switch kt.kind {
		case tokBare:
			p.advance()
			if strings.ContainsAny(kt.text, "*?") {
				p.stmtErr(kt.pos, "globs are not legal in label keys")
			} else {
				key = &ast.Value{Text: kt.text, Quoted: false, Pos: kt.pos}
			}
		case tokString:
			p.advance()
			key = &ast.Value{Text: kt.text, Quoted: true, Pos: kt.pos}
		default:
			p.stmtErr(kt.pos, "syntax error — expected a label key, found %s", kt.describe())
			p.advance()
		}
		if !p.at(tokEq) {
			p.stmtErr(p.cur().pos, "syntax error — expected `=` in label selector, found %s", p.cur().describe())
		} else {
			p.advance()
			ctxStr := "key="
			if key != nil {
				ctxStr = key.Text + "="
			}
			// Whitespace is legal around `=`, so no adjacency check here.
			if val := p.parseAttrValue(ctxStr, nil); val != nil && key != nil {
				pairs = append(pairs, ast.LabelPair{Key: *key, Value: *val})
			}
		}
		if p.at(tokComma) {
			p.advance()
			continue
		}
		if !p.at(tokRBrace) {
			p.stmtErr(p.cur().pos, "syntax error — expected `,` or `}`, found %s", p.cur().describe())
			break
		}
	}
	return &ast.Labels{Pairs: pairs, P: lb.pos}
}

// ── clauses ─────────────────────────────────────────────────────────

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
