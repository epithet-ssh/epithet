package writ

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

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

// parse parses policy source. The returned file holds every statement
// that parsed cleanly; statements with errors are dropped and reported.
func parse(src string) (*syntaxFile, []diag.Diagnostic) {
	toks, diags := lex(src)
	p := &parser{toks: toks, diags: diags}
	file := &syntaxFile{}
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

func (p *parser) parseStatement() syntaxItem {
	t := p.cur()
	if t.kind == tokBare {
		switch t.text {
		case "user":
			return p.parseMacroDef(kindUser)
		case "host":
			return p.parseMacroDef(kindHost)
		case "account":
			return p.parseMacroDef(kindAccount)
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

func (p *parser) parseMacroDef(kind syntaxKind) syntaxItem {
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
	return &syntaxMacroDef{Kind: kind, Name: name.text, Body: body, Pos: kw.pos}
}

func (p *parser) parseAllow() syntaxItem {
	kw := p.advance()
	users := p.parseExpr(kindUser, ctxAllow)
	if !p.expectHead(tokArrow, "`->`") {
		return nil
	}
	accounts := p.parseExpr(kindAccount, ctxAllow)
	if !p.expectHead(tokAt, "`@`") {
		return nil
	}
	hosts := p.parseExpr(kindHost, ctxAllow)
	clauses := p.parseClauses(false)
	p.expectTerm()
	return &syntaxAllowRule{Users: users, Accounts: accounts, Hosts: hosts, Clauses: clauses, Pos: kw.pos}
}

func (p *parser) parseDeny() syntaxItem {
	kw := p.advance()
	notUsers := p.eatBang()
	users := p.parseExpr(kindUser, ctxDeny)
	if !p.expectHead(tokArrow, "`->`") {
		return nil
	}
	notAccounts := p.eatBang()
	accounts := p.parseExpr(kindAccount, ctxDeny)
	if !p.expectHead(tokAt, "`@`") {
		return nil
	}
	notHosts := p.eatBang()
	hosts := p.parseExpr(kindHost, ctxDeny)
	clauses := p.parseClauses(true)
	p.expectTerm()
	return &syntaxDenyRule{
		Users:    syntaxNegExpr{Not: notUsers, Expr: users},
		Accounts: syntaxNegExpr{Not: notAccounts, Expr: accounts},
		Hosts:    syntaxNegExpr{Not: notHosts, Expr: hosts},
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

func (p *parser) parseExpr(kind syntaxKind, ctx negCtx) syntaxExpr {
	pos := p.cur().pos
	return syntaxExpr{Atom: p.parseAtom(kind, ctx), Pos: pos}
}

func (p *parser) parseAtom(kind syntaxKind, ctx negCtx) syntaxAtom {
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
		return &syntaxMacroRef{Name: t.text, P: t.pos}
	}
	if kind == kindUser {
		if t.kind == tokBare && t.text == "*" {
			p.advance()
			return &syntaxAny{P: t.pos}
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
			return &syntaxFilter{Object: t.text, Pairs: []syntaxPair{{Key: syntaxValue{Text: "name", Pos: t.pos}, Value: *v}}, P: t.pos}
		}
		if p.at(tokLBrace) {
			return p.parseFilter(t.text)
		}
		p.stmtErr(p.cur().pos, "expected ':' or '{' after %s", t.text)
		return nil
	}
	if t.kind == tokLBrace {
		f := p.parseFilter("host")
		if kind != kindHost {
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
	v := syntaxValue{Text: t.text, Quoted: t.kind == tokString, Pos: t.pos}
	if kind == kindAccount {
		if t.text == "*" {
			return &syntaxAny{P: t.pos}
		}
		return &syntaxName{Value: v}
	}
	if p.at(tokLBrace) {
		f := p.parseFilter("host")
		if t.text == "*" {
			p.stmtErr(t.pos, "use an attribute-only host filter instead of *{...}")
		}
		f.P = t.pos
		f.Pairs = append([]syntaxPair{{Key: syntaxValue{Text: "name", Pos: t.pos}, Value: v}}, f.Pairs...)
		return f
	}
	if t.text == "*" {
		return &syntaxAny{P: t.pos}
	}
	return &syntaxFilter{Object: "host", Pairs: []syntaxPair{{Key: syntaxValue{Text: "name", Pos: t.pos}, Value: v}}, P: t.pos}
}

func (p *parser) parseValue(pattern bool) *syntaxValue {
	t := p.cur()
	if t.kind != tokBare && t.kind != tokString {
		p.stmtErr(t.pos, "expected a string value")
		return nil
	}
	p.advance()
	if !pattern && t.kind == tokBare && strings.ContainsAny(t.text, "*?") {
		p.stmtErr(t.pos, "globs are only legal in host/account names; quote a literal wildcard")
	}
	return &syntaxValue{Text: t.text, Quoted: t.kind == tokString, Pos: t.pos}
}

func (p *parser) parseFilter(object string) *syntaxFilter {
	start := p.advance()
	f := &syntaxFilter{Object: object, P: start.pos}
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
		f.Pairs = append(f.Pairs, syntaxPair{Key: *key, Value: *value})
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

func (p *parser) parseClauses(isDeny bool) []syntaxClause {
	var clauses []syntaxClause
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
			clauses = append(clauses, &syntaxRequire{Names: names, P: kw.pos})
		case "when":
			names := p.parseNameList()
			clauses = append(clauses, &syntaxWhen{Names: names, P: kw.pos})
		case "until":
			s, ok := p.expectValue(tokString, "a quoted timestamp after `until`")
			if !ok {
				continue
			}
			if isDeny {
				p.stmtErr(kw.pos, "`until` is allow-only — a deny that loosens on a schedule needs a human; use a `when` flag")
				continue
			}
			if err := validateTimestamp(s.text); err != nil {
				p.stmtErr(s.pos, "%s", err)
				continue
			}
			clauses = append(clauses, &syntaxUntil{TS: syntaxValue{Text: s.text, Quoted: true, Pos: s.pos}, P: kw.pos})
		case "ttl":
			b, ok := p.expectValue(tokBare, "a duration after `ttl`")
			if !ok {
				continue
			}
			if isDeny {
				p.stmtErr(kw.pos, "`ttl` is allow-only — a deny issues nothing")
				continue
			}
			secs, err := parseDuration(b.text)
			if err != nil {
				p.stmtErr(b.pos, "%s", err)
				continue
			}
			clauses = append(clauses, &syntaxTTL{Seconds: secs, P: kw.pos})
		case "notify":
			targets := p.parseStringList()
			clauses = append(clauses, &syntaxNotify{Targets: targets, P: kw.pos})
		case "label":
			s, ok := p.expectValue(tokString, "a quoted string after `label`")
			if !ok {
				continue
			}
			clauses = append(clauses, &syntaxLabel{Value: syntaxValue{Text: s.text, Quoted: true, Pos: s.pos}, P: kw.pos})
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

func (p *parser) parseNameList() []syntaxValue {
	return p.parseValueList(func() (syntaxValue, bool) {
		t := p.cur()
		if t.kind != tokBare && t.kind != tokString {
			p.stmtErr(t.pos, "syntax error — expected a name, found %s", t.describe())
			return syntaxValue{}, false
		}
		p.advance()
		return syntaxValue{Text: t.text, Quoted: t.kind == tokString, Pos: t.pos}, true
	})
}

func (p *parser) parseStringList() []syntaxValue {
	return p.parseValueList(func() (syntaxValue, bool) {
		t := p.cur()
		if t.kind != tokString {
			p.stmtErr(t.pos, "syntax error — expected a quoted string, found %s", t.describe())
			return syntaxValue{}, false
		}
		p.advance()
		return syntaxValue{Text: t.text, Quoted: true, Pos: t.pos}, true
	})
}

func (p *parser) parseValueList(item func() (syntaxValue, bool)) []syntaxValue {
	var vals []syntaxValue
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

// Token validators, ported from the reference implementation.
// Timestamps and durations are ordinary tokens validated after parsing,
// not lexer modes (SPEC §3).

// maxDurationSeconds bounds a writ duration to what fits in a
// time.Duration (about 292 years), so downstream conversion to
// nanoseconds can never overflow.
const maxDurationSeconds = uint64(math.MaxInt64 / int64(time.Second))

// parseDuration parses a writ duration — integer plus s/m/h parts,
// composable: 2m, 90s, 1h30m — returning whole seconds. Zero is
// rejected: the IL uses zero as its "no ttl set" sentinel, and a
// zero-lifetime certificate is never what an author meant.
func parseDuration(s string) (uint64, error) {
	var total uint64
	num := ""
	any := false
	tooLarge := func() (uint64, error) {
		return 0, fmt.Errorf("invalid duration `%s` — too large", s)
	}
	for _, c := range s {
		if c >= '0' && c <= '9' {
			num += string(c)
			continue
		}
		var mult uint64
		switch c {
		case 's':
			mult = 1
		case 'm':
			mult = 60
		case 'h':
			mult = 3600
		default:
			return 0, fmt.Errorf("invalid duration `%s` — use integer s/m/h parts like 2m, 90s, 1h30m", s)
		}
		if num == "" {
			return 0, fmt.Errorf("invalid duration `%s` — unit `%c` has no number", s, c)
		}
		n, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			return tooLarge()
		}
		if n > maxDurationSeconds/mult {
			return tooLarge()
		}
		part := n * mult
		if total > maxDurationSeconds-part {
			return tooLarge()
		}
		total += part
		num = ""
		any = true
	}
	if num != "" {
		return 0, fmt.Errorf("invalid duration `%s` — trailing number without a unit", s)
	}
	if !any {
		return 0, fmt.Errorf("invalid duration `%s`", s)
	}
	if total == 0 {
		return 0, fmt.Errorf("invalid duration `%s` — must be positive", s)
	}
	return total, nil
}

// validateTimestamp shape-checks an RFC 3339 timestamp with a mandatory
// offset. Seconds may be omitted (the spec writes "2026-08-31T22:00Z").
// Calendar validity beyond cheap range checks is apply-time work.
func validateTimestamp(s string) error {
	b := []byte(s)
	fail := func() error {
		return fmt.Errorf("invalid timestamp `%s` — RFC 3339 with a mandatory offset, e.g. \"2026-08-31T22:00Z\" or \"...+02:00\"", s)
	}
	digit := func(i int) bool { return i < len(b) && b[i] >= '0' && b[i] <= '9' }
	at := func(i int, c byte) bool { return i < len(b) && b[i] == c }
	val := func(a, n int) int {
		v := 0
		for _, c := range b[a : a+n] {
			v = v*10 + int(c-'0')
		}
		return v
	}
	for i := range 4 {
		if !digit(i) {
			return fail()
		}
	}
	if !at(4, '-') || !digit(5) || !digit(6) || !at(7, '-') || !digit(8) || !digit(9) {
		return fail()
	}
	if !(at(10, 'T') || at(10, 't') || at(10, ' ')) {
		return fail()
	}
	if !digit(11) || !digit(12) || !at(13, ':') || !digit(14) || !digit(15) {
		return fail()
	}
	if m := val(5, 2); m < 1 || m > 12 {
		return fail()
	}
	if d := val(8, 2); d < 1 || d > 31 {
		return fail()
	}
	if val(11, 2) > 23 || val(14, 2) > 59 {
		return fail()
	}
	i := 16
	if at(i, ':') {
		if !digit(i+1) || !digit(i+2) || val(i+1, 2) > 60 {
			return fail()
		}
		i += 3
		if at(i, '.') {
			i++
			start := i
			for digit(i) {
				i++
			}
			if i == start {
				return fail()
			}
		}
	}
	switch {
	case at(i, 'Z') || at(i, 'z'):
		i++
	case at(i, '+') || at(i, '-'):
		if !digit(i+1) || !digit(i+2) || !at(i+3, ':') || !digit(i+4) || !digit(i+5) {
			return fail()
		}
		if val(i+1, 2) > 23 || val(i+4, 2) > 59 {
			return fail()
		}
		i += 6
	default:
		return fail()
	}
	if i != len(b) {
		return fail()
	}
	return nil
}
