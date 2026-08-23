// Package ast is the parsed form of a writ policy file, a direct port
// of the retired Rust spike's ast.rs (the porting reference named by
// SPEC §12.11). It preserves the shape the spec's IL depends on: allow
// rules carry plain expressions, deny rules carry negatable ones, so a
// negated allow is unrepresentable rather than validated away.
package ast

import "github.com/epithet-ssh/epithet/pkg/writ/diag"

// File is a parsed policy file: a sequence of macro definitions and rules.
type File struct {
	Items []Item
}

// Item is one statement: *MacroDef, *AllowRule, or *DenyRule.
type Item interface {
	isItem()
}

func (*MacroDef) isItem()  {}
func (*AllowRule) isItem() {}
func (*DenyRule) isItem()  {}

// Kind is one of the three matcher kinds. A macro declares one; every
// expression position implies one.
type Kind int

const (
	KindUser Kind = iota
	KindAccount
	KindHost
)

func (k Kind) String() string {
	switch k {
	case KindUser:
		return "user"
	case KindAccount:
		return "account"
	default:
		return "host"
	}
}

// MacroDef binds a name to a match expression of a declared kind.
type MacroDef struct {
	Kind Kind
	Name string
	Body Expr
	Pos  diag.Pos
}

// AllowRule carries plain expressions: negation on the allow path is
// unrepresentable, mirroring the IL's MatchSet / NegatableMatchSet split.
type AllowRule struct {
	Users    Expr
	Accounts Expr
	Hosts    Expr
	Clauses  []Clause
	Pos      diag.Pos
}

// DenyRule carries negatable expressions in all three positions.
type DenyRule struct {
	Users    NegExpr
	Accounts NegExpr
	Hosts    NegExpr
	Clauses  []Clause
	Pos      diag.Pos
}

// NegExpr is an expression plus a bit; `!` applies to the whole
// expression, never to an atom inside a list.
type NegExpr struct {
	Not bool
	Expr
}

// Expr is a union of atoms. Singletons parse to a one-element list;
// Bracketed records whether the author wrote `[...]` (for the formatter,
// later).
type Expr struct {
	Atoms     []Atom
	Bracketed bool
	Pos       diag.Pos
}

// Atom is one matcher in an expression: *MacroRef, *TagMatcher, *Name,
// *Labels, or *Any.
type Atom interface {
	Pos() diag.Pos
}

// MacroRef is `$name` — a splice of a same-kind macro.
type MacroRef struct {
	Name string
	P    diag.Pos
}

func (a *MacroRef) Pos() diag.Pos { return a.P }

// TagMatcher is `tag:value` — user position only.
type TagMatcher struct {
	Tag   Tag
	Value Value
}

func (a *TagMatcher) Pos() diag.Pos { return a.Value.Pos }

// Name is a bare or quoted account/host name; bare names may glob (`*`, `?`).
type Name struct {
	Value Value
}

func (a *Name) Pos() diag.Pos { return a.Value.Pos }

// Labels is `{k=v, ...}` — host position only; entries AND.
type Labels struct {
	Pairs []LabelPair
	P     diag.Pos
}

func (a *Labels) Pos() diag.Pos { return a.P }

// LabelPair is one `key=value` entry in a label selector.
type LabelPair struct {
	Key   Value
	Value Value
}

// Any is `*` — matches everything; kept distinct from a glob per the
// spec (a surface `*` compiles to {"any": true}, never {"glob": "*"}).
type Any struct {
	P diag.Pos
}

func (a *Any) Pos() diag.Pos { return a.P }

// Tag is one of the five user-matcher prefixes.
type Tag int

const (
	TagID Tag = iota
	TagGroup
	TagType
	TagDept
	TagOrg
)

func (t Tag) String() string {
	switch t {
	case TagID:
		return "id"
	case TagGroup:
		return "group"
	case TagType:
		return "type"
	case TagDept:
		return "dept"
	default:
		return "org"
	}
}

// TagOf maps a tag word to its Tag, reporting whether s names one.
func TagOf(s string) (Tag, bool) {
	switch s {
	case "id":
		return TagID, true
	case "group":
		return TagGroup, true
	case "type":
		return TagType, true
	case "dept":
		return TagDept, true
	case "org":
		return TagOrg, true
	}
	return 0, false
}

// Value is a scalar. Quoted matters for well-formedness: a quoted
// attribute value is always a literal, while a bare `*`/`?` in an
// attribute-value position is an error (SPEC §7 error 11).
type Value struct {
	Text   string
	Quoted bool
	Pos    diag.Pos
}

// Clause is one tail clause: *Require, *When, *Until, *TTL, *Notify, or
// *Label.
type Clause interface {
	Keyword() string
	Pos() diag.Pos
}

// Require names async facts that must all be satisfied (allow-only).
type Require struct {
	Names []Value
	P     diag.Pos
}

func (c *Require) Keyword() string { return "require" }
func (c *Require) Pos() diag.Pos   { return c.P }

// When names sync flags that must all currently hold.
type When struct {
	Names []Value
	P     diag.Pos
}

func (c *When) Keyword() string { return "when" }
func (c *When) Pos() diag.Pos   { return c.P }

// Until stops the rule matching at the given instant (allow-only).
type Until struct {
	TS Value
	P  diag.Pos
}

func (c *Until) Keyword() string { return "until" }
func (c *Until) Pos() diag.Pos   { return c.P }

// TTL overrides the deployment-default cert TTL (allow-only).
type TTL struct {
	Seconds uint64
	P       diag.Pos
}

func (c *TTL) Keyword() string { return "ttl" }
func (c *TTL) Pos() diag.Pos   { return c.P }

// Notify names fire-and-forget notification targets.
type Notify struct {
	Targets []Value
	P       diag.Pos
}

func (c *Notify) Keyword() string { return "notify" }
func (c *Notify) Pos() diag.Pos   { return c.P }

// Label is a human-readable alias for the rule; cosmetic only.
type Label struct {
	Value Value
	P     diag.Pos
}

func (c *Label) Keyword() string { return "label" }
func (c *Label) Pos() diag.Pos   { return c.P }
