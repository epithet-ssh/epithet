// Package ast is the parsed form of a Writ policy file. It retains predicates
// in authored order and keeps negation confined to deny selectors.
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
// selector position implies one.
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
// unrepresentable, mirroring the IL's Selector / NegatableSelector split.
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
// expression, never to a predicate within a filter.
type NegExpr struct {
	Not bool
	Expr
}

// Expr is one selector or macro reference.
type Expr struct {
	Atom Atom
	Pos  diag.Pos
}
type Atom interface{ Pos() diag.Pos }
type MacroRef struct {
	Name string
	P    diag.Pos
}

func (a *MacroRef) Pos() diag.Pos { return a.P }

// Filter is a conjunction on a user, group, or host object.
type Filter struct {
	Object string
	Pairs  []Pair
	P      diag.Pos
}

func (a *Filter) Pos() diag.Pos { return a.P }

type Pair struct {
	Key   Value
	Value Value
}

// Name is an account selector; its established glob semantics are retained.
type Name struct{ Value Value }

func (a *Name) Pos() diag.Pos { return a.Value.Pos }

// Any is the universal selector in its rule position.
type Any struct{ P diag.Pos }

func (a *Any) Pos() diag.Pos { return a.P }

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
