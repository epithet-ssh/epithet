package parser

import (
	"fmt"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/writ/diag"
)

// The lexer owns writ's newline discipline (SPEC §3): after comments
// are stripped, a newline terminates the statement when bracket depth
// is zero and the previous significant token is not a comma. There is
// no `\` continuation — an open bracket or a trailing comma is the
// continuation signal.

type tokKind int

const (
	tokBare tokKind = iota // bare word, including `*` and glob forms
	tokString              // quoted string; text is the unescaped value
	tokMacroRef            // $ident; text is the identifier
	tokBang                // !
	tokArrow               // ->
	tokAt                  // @
	tokColon               // :
	tokComma               // ,
	tokEq                  // =
	tokLBracket            // [
	tokRBracket            // ]
	tokLBrace              // {
	tokRBrace              // }
	tokTerm                // statement terminator
	tokEOF
)

type token struct {
	kind tokKind
	text string
	pos  diag.Pos
	// Byte offsets into the source, for the adjacency rules: `tag:value`
	// and `$ident` admit no interior whitespace.
	start, end int
}

func (t token) describe() string {
	switch t.kind {
	case tokBare:
		return fmt.Sprintf("`%s`", t.text)
	case tokString:
		return "a quoted string"
	case tokMacroRef:
		return fmt.Sprintf("`$%s`", t.text)
	case tokBang:
		return "`!`"
	case tokArrow:
		return "`->`"
	case tokAt:
		return "`@`"
	case tokColon:
		return "`:`"
	case tokComma:
		return "`,`"
	case tokEq:
		return "`=`"
	case tokLBracket:
		return "`[`"
	case tokRBracket:
		return "`]`"
	case tokLBrace:
		return "`{`"
	case tokRBrace:
		return "`}`"
	case tokTerm:
		return "end of statement"
	default:
		return "end of file"
	}
}

type lexer struct {
	src   string
	i     int
	line  int
	col   int
	depth int
	toks  []token
	diags []diag.Diagnostic
}

func isBareChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '.' || c == '*' || c == '?' || c == '/'
}

func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func isIdentChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func lex(src string) ([]token, []diag.Diagnostic) {
	l := &lexer{src: src, line: 1, col: 1}
	l.run()
	return l.toks, l.diags
}

func (l *lexer) pos() diag.Pos { return diag.Pos{Line: l.line, Col: l.col} }

func (l *lexer) errf(pos diag.Pos, format string, args ...any) {
	l.diags = append(l.diags, diag.Errorf(pos, format, args...))
}

// advance moves past one byte, updating line/col. Multi-byte UTF-8
// sequences only occur inside strings and comments; col counts their
// leading byte once and skips continuation bytes.
func (l *lexer) advance() {
	c := l.src[l.i]
	l.i++
	if c == '\n' {
		l.line++
		l.col = 1
		return
	}
	// Do not count UTF-8 continuation bytes as columns.
	if c&0xC0 != 0x80 {
		l.col++
	}
}

func (l *lexer) emit(kind tokKind, text string, pos diag.Pos, start int) {
	l.toks = append(l.toks, token{kind: kind, text: text, pos: pos, start: start, end: l.i})
}

// last returns the most recent token, or nil.
func (l *lexer) last() *token {
	if len(l.toks) == 0 {
		return nil
	}
	return &l.toks[len(l.toks)-1]
}

func (l *lexer) run() {
	for l.i < len(l.src) {
		c := l.src[l.i]
		pos := l.pos()
		start := l.i
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			l.advance()
		case c == '#':
			for l.i < len(l.src) && l.src[l.i] != '\n' {
				l.advance()
			}
		case c == '\n':
			l.newline()
			l.advance()
		case c == '"':
			l.lexString()
		case c == '$':
			l.advance()
			if l.i < len(l.src) && isIdentStart(l.src[l.i]) {
				name := l.lexIdent()
				l.emit(tokMacroRef, name, pos, start)
			} else {
				l.errf(pos, "`$` must be immediately followed by a macro name")
			}
		case c == '-':
			l.advance()
			if l.i < len(l.src) && l.src[l.i] == '>' {
				l.advance()
				l.emit(tokArrow, "->", pos, start)
			} else {
				l.errf(pos, "unexpected `-` — a bare word may contain but not begin with `-`")
			}
		case c == '[':
			l.depth++
			l.advance()
			l.emit(tokLBracket, "[", pos, start)
		case c == ']':
			l.closeBracket()
			l.advance()
			l.emit(tokRBracket, "]", pos, start)
		case c == '{':
			l.depth++
			l.advance()
			l.emit(tokLBrace, "{", pos, start)
		case c == '}':
			l.closeBracket()
			l.advance()
			l.emit(tokRBrace, "}", pos, start)
		case c == ',':
			l.advance()
			l.emit(tokComma, ",", pos, start)
		case c == '=':
			l.advance()
			l.emit(tokEq, "=", pos, start)
		case c == ':':
			l.advance()
			l.emit(tokColon, ":", pos, start)
		case c == '@':
			l.advance()
			l.emit(tokAt, "@", pos, start)
		case c == '!':
			l.advance()
			l.emit(tokBang, "!", pos, start)
		case isBareChar(c):
			text := l.lexBare()
			l.emit(tokBare, text, pos, start)
		default:
			// Advance over the full UTF-8 sequence so the error names
			// the character, not its first byte.
			r := []rune(l.src[l.i:])[0]
			l.errf(pos, "unexpected character `%c`", r)
			for range len(string(r)) {
				l.advance()
			}
		}
	}
	l.finish()
}

// newline implements the statement-termination rule at a `\n`.
func (l *lexer) newline() {
	if l.depth > 0 {
		return
	}
	last := l.last()
	if last == nil || last.kind == tokTerm || last.kind == tokComma {
		return
	}
	l.emit(tokTerm, "", l.pos(), l.i)
}

func (l *lexer) closeBracket() {
	if l.depth > 0 {
		l.depth--
	}
}

func (l *lexer) finish() {
	last := l.last()
	// SPEC §7 error 12: a depth-0 trailing comma immediately before EOF
	// promises a clause that never arrives. Drop the comma so the
	// statement still terminates and the file reports exactly one error.
	if l.depth == 0 && last != nil && last.kind == tokComma {
		l.errf(last.pos, "trailing comma at end of file — a `,` at the end of a line continues the statement, but nothing follows")
		l.toks = l.toks[:len(l.toks)-1]
		last = l.last()
	}
	if last != nil && last.kind != tokTerm {
		l.emit(tokTerm, "", l.pos(), l.i)
	}
	l.emit(tokEOF, "", l.pos(), l.i)
}

// lexBare scans a bare word: runs of bare chars, with interior hyphen
// runs consumed only when more bare chars follow. That trailing-hyphen
// rule is what lets `$sre->root` lex without whitespace.
func (l *lexer) lexBare() string {
	start := l.i
	for l.i < len(l.src) && isBareChar(l.src[l.i]) {
		l.advance()
	}
	for l.i < len(l.src) && l.src[l.i] == '-' {
		j := l.i
		for j < len(l.src) && l.src[j] == '-' {
			j++
		}
		if j >= len(l.src) || !isBareChar(l.src[j]) {
			break
		}
		for l.i < j {
			l.advance()
		}
		for l.i < len(l.src) && isBareChar(l.src[l.i]) {
			l.advance()
		}
	}
	return l.src[start:l.i]
}

// lexIdent scans a macro identifier: [A-Za-z_][A-Za-z0-9_]* with
// interior (never trailing) hyphen runs.
func (l *lexer) lexIdent() string {
	start := l.i
	for l.i < len(l.src) && isIdentChar(l.src[l.i]) {
		l.advance()
	}
	for l.i < len(l.src) && l.src[l.i] == '-' {
		j := l.i
		for j < len(l.src) && l.src[j] == '-' {
			j++
		}
		if j >= len(l.src) || !isIdentChar(l.src[j]) {
			break
		}
		for l.i < j {
			l.advance()
		}
		for l.i < len(l.src) && isIdentChar(l.src[l.i]) {
			l.advance()
		}
	}
	return l.src[start:l.i]
}

// lexString scans a double-quoted string with exactly two escapes,
// `\"` and `\\`. No newlines inside strings; UTF-8 passes through.
func (l *lexer) lexString() {
	pos := l.pos()
	start := l.i
	l.advance() // opening quote
	var sb strings.Builder
	for {
		if l.i >= len(l.src) || l.src[l.i] == '\n' {
			l.errf(pos, "unterminated string")
			l.emit(tokString, sb.String(), pos, start)
			return
		}
		c := l.src[l.i]
		switch c {
		case '"':
			l.advance()
			l.emit(tokString, sb.String(), pos, start)
			return
		case '\\':
			l.advance()
			if l.i >= len(l.src) || (l.src[l.i] != '"' && l.src[l.i] != '\\') {
				l.errf(pos, `invalid escape in string — only \" and \\ are recognized`)
				continue
			}
			sb.WriteByte(l.src[l.i])
			l.advance()
		default:
			sb.WriteByte(c)
			l.advance()
		}
	}
}
