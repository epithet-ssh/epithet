package writ

import "github.com/epithet-ssh/epithet/pkg/writ/diag"

// syntaxFile is a parsed policy file: a sequence of macro definitions and rules.
type syntaxFile struct {
	Items []syntaxItem
}

// syntaxItem is one statement: *syntaxMacroDef, *syntaxAllowRule, or *syntaxDenyRule.
type syntaxItem interface {
	isItem()
}

func (*syntaxMacroDef) isItem()  {}
func (*syntaxAllowRule) isItem() {}
func (*syntaxDenyRule) isItem()  {}

// syntaxKind is one of the three matcher kinds. A macro declares one; every
// selector position implies one.
type syntaxKind int

const (
	kindUser syntaxKind = iota
	kindAccount
	kindHost
)

func (k syntaxKind) String() string {
	switch k {
	case kindUser:
		return "user"
	case kindAccount:
		return "account"
	default:
		return "host"
	}
}

// syntaxMacroDef binds a name to a match expression of a declared kind.
type syntaxMacroDef struct {
	Kind syntaxKind
	Name string
	Body syntaxExpr
	Pos  diag.Pos
}

// syntaxAllowRule carries plain expressions: negation on the allow path is
// unrepresentable, mirroring the IL's Selector / NegatableSelector split.
type syntaxAllowRule struct {
	Users    syntaxExpr
	Accounts syntaxExpr
	Hosts    syntaxExpr
	Clauses  []syntaxClause
	Pos      diag.Pos
}

// syntaxDenyRule carries negatable expressions in all three positions.
type syntaxDenyRule struct {
	Users    syntaxNegExpr
	Accounts syntaxNegExpr
	Hosts    syntaxNegExpr
	Clauses  []syntaxClause
	Pos      diag.Pos
}

// syntaxNegExpr is an expression plus a bit; `!` applies to the whole
// expression, never to a predicate within a filter.
type syntaxNegExpr struct {
	Not  bool
	Expr syntaxExpr
}

// syntaxExpr is one selector or macro reference.
type syntaxExpr struct {
	Atom syntaxAtom
	Pos  diag.Pos
}
type syntaxAtom interface{ Pos() diag.Pos }
type syntaxMacroRef struct {
	Name string
	P    diag.Pos
}

func (a *syntaxMacroRef) Pos() diag.Pos { return a.P }

// syntaxFilter is a conjunction on a user, group, or host object.
type syntaxFilter struct {
	Object string
	Pairs  []syntaxPair
	P      diag.Pos
}

func (a *syntaxFilter) Pos() diag.Pos { return a.P }

type syntaxPair struct {
	Key   syntaxValue
	Value syntaxValue
}

// syntaxName is an account selector; its established glob semantics are retained.
type syntaxName struct{ Value syntaxValue }

func (a *syntaxName) Pos() diag.Pos { return a.Value.Pos }

// syntaxAny is the universal selector in its rule position.
type syntaxAny struct{ P diag.Pos }

func (a *syntaxAny) Pos() diag.Pos { return a.P }

// syntaxValue is a scalar. Quoted matters for well-formedness: a quoted
// attribute value is always a literal, while a bare `*`/`?` in an
// attribute-value position is an error (SPEC §7 error 11).
type syntaxValue struct {
	Text   string
	Quoted bool
	Pos    diag.Pos
}

// syntaxClause is one tail clause: *syntaxRequire, *syntaxWhen, *syntaxUntil, *syntaxTTL, *syntaxNotify, or
// *syntaxLabel.
type syntaxClause interface {
	Keyword() string
	Pos() diag.Pos
}

// syntaxRequire names async facts that must all be satisfied (allow-only).
type syntaxRequire struct {
	Names []syntaxValue
	P     diag.Pos
}

func (c *syntaxRequire) Keyword() string { return "require" }
func (c *syntaxRequire) Pos() diag.Pos   { return c.P }

// syntaxWhen names sync flags that must all currently hold.
type syntaxWhen struct {
	Names []syntaxValue
	P     diag.Pos
}

func (c *syntaxWhen) Keyword() string { return "when" }
func (c *syntaxWhen) Pos() diag.Pos   { return c.P }

// syntaxUntil stops the rule matching at the given instant (allow-only).
type syntaxUntil struct {
	TS syntaxValue
	P  diag.Pos
}

func (c *syntaxUntil) Keyword() string { return "until" }
func (c *syntaxUntil) Pos() diag.Pos   { return c.P }

// syntaxTTL overrides the deployment-default cert TTL (allow-only).
type syntaxTTL struct {
	Seconds uint64
	P       diag.Pos
}

func (c *syntaxTTL) Keyword() string { return "ttl" }
func (c *syntaxTTL) Pos() diag.Pos   { return c.P }

// syntaxNotify names fire-and-forget notification targets.
type syntaxNotify struct {
	Targets []syntaxValue
	P       diag.Pos
}

func (c *syntaxNotify) Keyword() string { return "notify" }
func (c *syntaxNotify) Pos() diag.Pos   { return c.P }

// syntaxLabel is a human-readable alias for the rule; cosmetic only.
type syntaxLabel struct {
	Value syntaxValue
	P     diag.Pos
}

func (c *syntaxLabel) Keyword() string { return "label" }
func (c *syntaxLabel) Pos() diag.Pos   { return c.P }
