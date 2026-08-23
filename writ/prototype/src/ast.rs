use crate::diag::Pos;

#[derive(Debug)]
pub struct File {
    pub items: Vec<Item>,
}

#[derive(Debug)]
pub enum Item {
    Macro(MacroDef),
    Allow(AllowRule),
    Deny(DenyRule),
}

/// The three matcher kinds. A macro declares one; every expression position
/// implies one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    User,
    Account,
    Host,
}

pub fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::User => "user",
        Kind::Account => "account",
        Kind::Host => "host",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug)]
pub struct MacroDef {
    pub kind: Kind,
    pub name: String,
    pub body: Expr,
    pub pos: Pos,
}

/// Allow rules carry plain expressions: negation on the allow path is
/// unrepresentable, mirroring 7.md's MatchSet / NegatableMatchSet split.
#[derive(Debug)]
pub struct AllowRule {
    pub users: Expr,
    pub accounts: Expr,
    pub hosts: Expr,
    pub clauses: Vec<Clause>,
    pub pos: Pos,
}

#[derive(Debug)]
pub struct DenyRule {
    pub users: NegExpr,
    pub accounts: NegExpr,
    pub hosts: NegExpr,
    pub clauses: Vec<Clause>,
    pub pos: Pos,
}

/// A negatable expression is an expression plus a bit; `!` applies to the
/// whole expression, never to an atom inside a list.
#[derive(Debug)]
pub struct NegExpr {
    pub not: bool,
    pub expr: Expr,
}

/// A union of atoms. Singletons parse to a one-element list; `bracketed`
/// records whether the author wrote `[...]` (for the formatter, later).
#[derive(Debug)]
pub struct Expr {
    pub atoms: Vec<Atom>,
    pub bracketed: bool,
    pub pos: Pos,
}

#[derive(Debug)]
pub enum Atom {
    /// `$name` — a splice of a same-kind macro.
    MacroRef { name: String, pos: Pos },
    /// `tag:value` — user position only.
    Tag { tag: Tag, value: Value },
    /// A bare or quoted account/host name; bare names may glob (`*`, `?`).
    Name(Value),
    /// `{k=v, ...}` — host position only; entries AND.
    Labels { pairs: Vec<(Value, Value)>, pos: Pos },
    /// `*` — matches everything; kept distinct from a glob per 7.md.
    Any(Pos),
}

impl Atom {
    pub fn pos(&self) -> Pos {
        match self {
            Atom::MacroRef { pos, .. } => *pos,
            Atom::Tag { value, .. } => value.pos,
            Atom::Name(v) => v.pos,
            Atom::Labels { pos, .. } => *pos,
            Atom::Any(pos) => *pos,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Id,
    Group,
    Type,
    Dept,
    Org,
}

pub fn tag_of(s: &str) -> Option<Tag> {
    Some(match s {
        "id" => Tag::Id,
        "group" => Tag::Group,
        "type" => Tag::Type,
        "dept" => Tag::Dept,
        "org" => Tag::Org,
        _ => return None,
    })
}

/// A scalar value. `quoted` matters for well-formedness: a quoted attribute
/// value is always a literal, while a bare `*`/`?` in an attribute-value
/// position is an error (7.md rule 10).
#[derive(Debug, Clone)]
pub struct Value {
    pub text: String,
    pub quoted: bool,
    pub pos: Pos,
}

#[derive(Debug)]
pub enum Clause {
    Require { names: Vec<Value>, pos: Pos },
    When { names: Vec<Value>, pos: Pos },
    Until { ts: Value, pos: Pos },
    Ttl { seconds: u64, pos: Pos },
    Notify { targets: Vec<Value>, pos: Pos },
    Label { value: Value, pos: Pos },
}

impl Clause {
    pub fn keyword(&self) -> &'static str {
        match self {
            Clause::Require { .. } => "require",
            Clause::When { .. } => "when",
            Clause::Until { .. } => "until",
            Clause::Ttl { .. } => "ttl",
            Clause::Notify { .. } => "notify",
            Clause::Label { .. } => "label",
        }
    }

    pub fn pos(&self) -> Pos {
        match self {
            Clause::Require { pos, .. }
            | Clause::When { pos, .. }
            | Clause::Until { pos, .. }
            | Clause::Ttl { pos, .. }
            | Clause::Notify { pos, .. }
            | Clause::Label { pos, .. } => *pos,
        }
    }
}
