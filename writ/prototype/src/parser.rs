use pest::iterators::Pair;
use pest::Parser as _;
use pest_derive::Parser;

use crate::ast::*;
use crate::diag::{Error, Pos};

#[derive(Parser)]
#[grammar = "grammar.pest"]
struct WritParser;

const KEYWORDS: &[&str] = &[
    "allow", "deny", "user", "host", "account", "require", "when", "until", "ttl", "notify", "label",
];

/// Parse a policy source into the AST. Statements that fail lowering are
/// dropped and reported; a pest syntax error aborts the whole file (pest
/// does not recover), which is the main diagnostic trade-off vs a
/// hand-rolled parser.
pub fn parse(src: &str) -> (File, Vec<Error>) {
    let file_pair = match WritParser::parse(Rule::file, src) {
        Ok(mut pairs) => pairs.next().expect("grammar always produces a file pair"),
        Err(e) => return (File { items: Vec::new() }, vec![convert(e)]),
    };
    let mut lower = Lower { errors: Vec::new() };
    let mut items = Vec::new();
    for p in file_pair.into_inner() {
        if p.as_rule() == Rule::EOI {
            continue;
        }
        if let Some(item) = lower.item(p) {
            items.push(item);
        }
    }
    (File { items }, lower.errors)
}

fn pos_of(p: &Pair<Rule>) -> Pos {
    let (line, col) = p.line_col();
    Pos { line: line as u32, col: col as u32 }
}

fn is_kw(r: Rule) -> bool {
    matches!(
        r,
        Rule::kw_user
            | Rule::kw_host
            | Rule::kw_account
            | Rule::kw_allow
            | Rule::kw_deny
            | Rule::kw_require
            | Rule::kw_when
            | Rule::kw_until
            | Rule::kw_ttl
            | Rule::kw_notify
            | Rule::kw_label
    )
}

/// Where a match expression sits, for negation diagnostics.
#[derive(Clone, Copy, PartialEq)]
enum NegCtx {
    Allow,
    Deny,
    MacroBody,
}

struct Lower {
    errors: Vec<Error>,
}

impl Lower {
    fn err(&mut self, pos: Pos, msg: impl Into<String>) {
        self.errors.push(Error { pos, msg: msg.into() });
    }

    fn item(&mut self, p: Pair<Rule>) -> Option<Item> {
        match p.as_rule() {
            Rule::user_macro => self.macro_def(p, Kind::User),
            Rule::host_macro => self.macro_def(p, Kind::Host),
            Rule::acct_macro => self.macro_def(p, Kind::Account),
            Rule::allow_rule => self.allow_rule(p),
            Rule::deny_rule => self.deny_rule(p),
            Rule::bad_neg_stmt => {
                let pos = pos_of(&p);
                self.err(pos, "negation is only legal on deny rules — write `deny !...`");
                None
            }
            Rule::bad_headless_rule => {
                let pos = pos_of(&p);
                self.err(pos, "missing `allow` — rules are `allow <users> -> <accounts>@<hosts>` or `deny ...`");
                None
            }
            r => unreachable!("unexpected item rule {r:?}"),
        }
    }

    fn macro_def(&mut self, p: Pair<Rule>, kind: Kind) -> Option<Item> {
        let pos = pos_of(&p);
        let mut inner = p.into_inner().filter(|c| !is_kw(c.as_rule()));
        let ident = inner.next().expect("macro_def has an ident");
        let name = ident.as_str().to_string();
        let npos = pos_of(&ident);
        let body_pair = inner.next().expect("macro_def has a body");
        if KEYWORDS.contains(&name.as_str()) {
            self.err(npos, format!("`{name}` is a keyword and cannot name a macro"));
            return None;
        }
        let body = self.expr(body_pair, kind, NegCtx::MacroBody)?;
        Some(Item::Macro(MacroDef { kind, name, body, pos }))
    }

    fn allow_rule(&mut self, p: Pair<Rule>) -> Option<Item> {
        let pos = pos_of(&p);
        let mut inner = p.into_inner().filter(|c| !is_kw(c.as_rule()));
        let users = self.expr(inner.next().expect("allow users"), Kind::User, NegCtx::Allow);
        let accounts = self.expr(inner.next().expect("allow accounts"), Kind::Account, NegCtx::Allow);
        let hosts = self.expr(inner.next().expect("allow hosts"), Kind::Host, NegCtx::Allow);
        let mut clauses = Vec::new();
        let mut bad = false;
        for cp in inner {
            match self.clause(cp) {
                Some(c) => clauses.push(c),
                None => bad = true,
            }
        }
        // Lower everything first so a broken head still reports clause errors.
        let (users, accounts, hosts) = (users?, accounts?, hosts?);
        if bad {
            return None;
        }
        Some(Item::Allow(AllowRule { users, accounts, hosts, clauses, pos }))
    }

    fn deny_rule(&mut self, p: Pair<Rule>) -> Option<Item> {
        let pos = pos_of(&p);
        let mut not = [false; 3];
        let mut slot = 0;
        let mut exprs: Vec<Option<NegExpr>> = Vec::new();
        let mut clauses = Vec::new();
        let mut bad = false;
        for c in p.into_inner() {
            match c.as_rule() {
                Rule::kw_deny => {}
                Rule::bang => not[slot] = true,
                Rule::user_expr => {
                    let e = self.expr(c, Kind::User, NegCtx::Deny);
                    exprs.push(e.map(|expr| NegExpr { not: not[0], expr }));
                    slot = 1;
                }
                Rule::acct_expr => {
                    let e = self.expr(c, Kind::Account, NegCtx::Deny);
                    exprs.push(e.map(|expr| NegExpr { not: not[1], expr }));
                    slot = 2;
                }
                Rule::host_expr => {
                    let e = self.expr(c, Kind::Host, NegCtx::Deny);
                    exprs.push(e.map(|expr| NegExpr { not: not[2], expr }));
                }
                _ => match self.clause(c) {
                    Some(cl) => clauses.push(cl),
                    None => bad = true,
                },
            }
        }
        if bad || exprs.len() != 3 || exprs.iter().any(|e| e.is_none()) {
            return None;
        }
        let mut it = exprs.into_iter().map(|e| e.expect("checked above"));
        Some(Item::Deny(DenyRule {
            users: it.next().expect("three exprs"),
            accounts: it.next().expect("three exprs"),
            hosts: it.next().expect("three exprs"),
            clauses,
            pos,
        }))
    }

    // ── expressions ─────────────────────────────────────────────────

    fn expr(&mut self, p: Pair<Rule>, kind: Kind, ctx: NegCtx) -> Option<Expr> {
        let pos = pos_of(&p);
        let child = p.into_inner().next().expect("expr has a child");
        let (atom_pairs, bracketed) = match child.as_rule() {
            Rule::user_list | Rule::acct_list | Rule::host_list => {
                (child.into_inner().collect::<Vec<_>>(), true)
            }
            _ => (vec![child], false),
        };
        let mut atoms = Vec::new();
        let mut bad = false;
        for ap in atom_pairs {
            match self.atom(ap, kind, ctx, bracketed) {
                Some(a) => atoms.push(a),
                None => bad = true,
            }
        }
        if bad {
            return None;
        }
        Some(Expr { atoms, bracketed, pos })
    }

    fn atom(&mut self, p: Pair<Rule>, kind: Kind, ctx: NegCtx, in_list: bool) -> Option<Atom> {
        let pos = pos_of(&p);
        match p.as_rule() {
            Rule::user_bang | Rule::acct_bang | Rule::host_bang => {
                let msg = match ctx {
                    NegCtx::MacroBody => {
                        "negation is not allowed in macro bodies — macros are purely positive"
                    }
                    NegCtx::Allow => "negation is only legal on deny rules",
                    NegCtx::Deny if in_list => {
                        "negation applies to the whole expression — write `![$a, $b]`, not `[!$a, !$b]`"
                    }
                    NegCtx::Deny => "unexpected `!` — negation already applies to the whole expression",
                };
                self.err(pos, msg);
                None
            }
            Rule::macro_ref => {
                let ident = p.into_inner().next().expect("macro_ref has ident");
                Some(Atom::MacroRef { name: ident.as_str().to_string(), pos })
            }
            Rule::tag_matcher => {
                let mut inner = p.into_inner();
                let tag_pair = inner.next().expect("tag_matcher has tag");
                let tag = tag_of(tag_pair.as_str()).expect("grammar admits only known tags");
                let ctx_str = format!("{}:", tag_pair.as_str());
                let value = self.attr_value(inner.next().expect("tag_matcher has value"), &ctx_str)?;
                Some(Atom::Tag { tag, value })
            }
            Rule::user_bare => {
                let inner = p.into_inner().next().expect("user_bare has a child");
                match inner.as_rule() {
                    Rule::bare if inner.as_str() == "*" => Some(Atom::Any(pos)),
                    Rule::bare => {
                        let s = inner.as_str();
                        if tag_of(s).is_some() {
                            self.err(pos, format!("expected `:` after user tag `{s}`"));
                        } else {
                            self.err(pos, format!(
                                "bare words are not user matchers — identity is opaque; use `id:\"{s}\"` or a tag matcher (id, group, type, dept, org)"
                            ));
                        }
                        None
                    }
                    Rule::string => {
                        self.err(pos, "a quoted string alone is not a user matcher — use `id:\"...\"`, `group:\"...\"`, etc.");
                        None
                    }
                    r => unreachable!("unexpected user_bare child {r:?}"),
                }
            }
            Rule::acct_name | Rule::host_name => {
                let inner = p.into_inner().next().expect("name has a child");
                match inner.as_rule() {
                    Rule::bare if inner.as_str() == "*" => Some(Atom::Any(pos)),
                    Rule::bare => {
                        let s = inner.as_str();
                        if s.contains('/') {
                            self.err(pos, format!("`/` is not legal in a bare name — quote \"{s}\" if the name really contains `/`"));
                            return None;
                        }
                        Some(Atom::Name(Value { text: s.to_string(), quoted: false, pos }))
                    }
                    Rule::string => Some(Atom::Name(string_value(inner))),
                    r => unreachable!("unexpected name child {r:?}"),
                }
            }
            Rule::label_sel => {
                let mut pairs = Vec::new();
                let mut bad = false;
                for eq in p.into_inner() {
                    let mut kv = eq.into_inner();
                    let kp = kv.next().expect("label_eq has key");
                    let vp = kv.next().expect("label_eq has value");
                    let key = match kp.as_rule() {
                        Rule::bare => {
                            let s = kp.as_str();
                            let kpos = pos_of(&kp);
                            if s.contains('*') || s.contains('?') {
                                self.err(kpos, "globs are not legal in label keys");
                                bad = true;
                                continue;
                            }
                            Value { text: s.to_string(), quoted: false, pos: kpos }
                        }
                        Rule::string => string_value(kp),
                        r => unreachable!("unexpected label key {r:?}"),
                    };
                    let ctx_str = format!("{}=", key.text);
                    match self.attr_value(vp, &ctx_str) {
                        Some(v) => pairs.push((key, v)),
                        None => bad = true,
                    }
                }
                if kind != Kind::Host {
                    // Unreachable via the grammar (label_sel is host-only),
                    // but keep the invariant visible.
                    unreachable!("label selector outside host position");
                }
                if bad {
                    return None;
                }
                Some(Atom::Labels { pairs, pos })
            }
            r => unreachable!("unexpected atom rule {r:?}"),
        }
    }

    /// An attribute value (after `tag:` or `key=`). Globs match names,
    /// never attribute values (7.md well-formedness rule 10); a quoted
    /// value is always a literal.
    fn attr_value(&mut self, p: Pair<Rule>, ctx: &str) -> Option<Value> {
        let pos = pos_of(&p);
        match p.as_rule() {
            Rule::bare => {
                let s = p.as_str();
                if s.contains('*') || s.contains('?') {
                    self.err(pos, format!(
                        "globs match names, never attribute values — quote the value (`{ctx}\"{s}\"`) to match a literal, or use a union of exact values"
                    ));
                    return None;
                }
                Some(Value { text: s.to_string(), quoted: false, pos })
            }
            Rule::string => Some(string_value(p)),
            r => unreachable!("unexpected attribute value {r:?}"),
        }
    }

    // ── clauses ─────────────────────────────────────────────────────

    fn clause(&mut self, p: Pair<Rule>) -> Option<Clause> {
        let pos = pos_of(&p);
        match p.as_rule() {
            Rule::require_c => Some(Clause::Require { names: self.name_values(p), pos }),
            Rule::when_c => Some(Clause::When { names: self.name_values(p), pos }),
            Rule::until_c => {
                let sp = p.into_inner().find(|c| c.as_rule() == Rule::string).expect("until has string");
                let ts = string_value(sp);
                match validate_timestamp(&ts.text) {
                    Ok(()) => Some(Clause::Until { ts, pos }),
                    Err(m) => {
                        let tpos = ts.pos;
                        self.err(tpos, m);
                        None
                    }
                }
            }
            Rule::ttl_c => {
                let bp = p.into_inner().find(|c| c.as_rule() == Rule::bare).expect("ttl has bare");
                let bpos = pos_of(&bp);
                match parse_duration(bp.as_str()) {
                    Ok(seconds) => Some(Clause::Ttl { seconds, pos }),
                    Err(m) => {
                        self.err(bpos, m);
                        None
                    }
                }
            }
            Rule::notify_c => {
                let targets = p
                    .into_inner()
                    .filter(|c| c.as_rule() == Rule::string)
                    .map(string_value)
                    .collect();
                Some(Clause::Notify { targets, pos })
            }
            Rule::label_c => {
                let sp = p.into_inner().find(|c| c.as_rule() == Rule::string).expect("label has string");
                Some(Clause::Label { value: string_value(sp), pos })
            }
            Rule::deny_illegal_c => {
                let first = p.into_inner().next().expect("illegal clause has keyword");
                let msg = match first.as_rule() {
                    Rule::kw_require => "`require` is not legal on a deny rule — a failed async check must not fail open",
                    Rule::kw_until => "`until` is allow-only — a deny that loosens on a schedule needs a human; use a `when` flag",
                    Rule::kw_ttl => "`ttl` is allow-only — a deny issues nothing",
                    r => unreachable!("unexpected illegal clause keyword {r:?}"),
                };
                self.err(pos, msg);
                None
            }
            r => unreachable!("unexpected clause rule {r:?}"),
        }
    }

    fn name_values(&mut self, p: Pair<Rule>) -> Vec<Value> {
        p.into_inner()
            .filter(|c| c.as_rule() == Rule::name_item)
            .map(|np| {
                let inner = np.into_inner().next().expect("name_item has a child");
                match inner.as_rule() {
                    Rule::bare => Value {
                        text: inner.as_str().to_string(),
                        quoted: false,
                        pos: pos_of(&inner),
                    },
                    Rule::string => string_value(inner),
                    r => unreachable!("unexpected name child {r:?}"),
                }
            })
            .collect()
    }
}

fn string_value(p: Pair<Rule>) -> Value {
    let pos = pos_of(&p);
    let raw = p.into_inner().next().expect("string has inner").as_str();
    Value { text: unescape(raw), quoted: true, pos }
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ── pest error conversion ───────────────────────────────────────────

fn convert(e: pest::error::Error<Rule>) -> Error {
    use pest::error::{ErrorVariant, LineColLocation};
    let (line, col) = match e.line_col {
        LineColLocation::Pos((l, c)) => (l, c),
        LineColLocation::Span((l, c), _) => (l, c),
    };
    let msg = match &e.variant {
        ErrorVariant::ParsingError { positives, .. } => {
            let mut names: Vec<&str> = positives.iter().map(|r| rule_name(*r)).collect();
            names.sort_unstable();
            names.dedup();
            format!("syntax error — expected {}", names.join(", "))
        }
        ErrorVariant::CustomError { message } => message.clone(),
    };
    Error { pos: Pos { line: line as u32, col: col as u32 }, msg }
}

fn rule_name(r: Rule) -> &'static str {
    match r {
        Rule::file => "a policy file",
        Rule::user_macro | Rule::host_macro | Rule::acct_macro => "a macro definition",
        Rule::allow_rule | Rule::kw_allow => "`allow`",
        Rule::deny_rule | Rule::kw_deny => "`deny`",
        Rule::user_expr | Rule::user_list | Rule::tag_matcher | Rule::tag => "a user matcher",
        Rule::acct_expr | Rule::acct_list | Rule::acct_name => "an account matcher",
        Rule::host_expr | Rule::host_list | Rule::host_name => "a host matcher",
        Rule::label_sel | Rule::label_eq => "a `{key=value}` selector",
        Rule::macro_ref => "`$macro`",
        Rule::kw_require => "`require`",
        Rule::kw_when => "`when`",
        Rule::kw_until => "`until`",
        Rule::kw_ttl => "`ttl`",
        Rule::kw_notify => "`notify`",
        Rule::kw_label => "`label`",
        Rule::require_c | Rule::when_c | Rule::until_c | Rule::ttl_c | Rule::notify_c
        | Rule::label_c => "a clause (require, when, until, ttl, notify, label)",
        Rule::string | Rule::str_inner => "a quoted string",
        Rule::bare | Rule::name_item => "a name",
        Rule::ident => "an identifier",
        Rule::bang => "`!`",
        Rule::EOI => "end of file",
        _ => "valid syntax",
    }
}

// ── token validators ────────────────────────────────────────────────

/// Durations are integer+unit parts, composable: 2m, 90s, 1h30m.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let mut total: u64 = 0;
    let mut num = String::new();
    let mut any = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let mult = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return Err(format!("invalid duration `{s}` — use integer s/m/h parts like 2m, 90s, 1h30m")),
        };
        if num.is_empty() {
            return Err(format!("invalid duration `{s}` — unit `{c}` has no number"));
        }
        let n: u64 = num.parse().map_err(|_| format!("invalid duration `{s}`"))?;
        total = total.saturating_add(n.saturating_mul(mult));
        num.clear();
        any = true;
    }
    if !num.is_empty() {
        return Err(format!("invalid duration `{s}` — trailing number without a unit"));
    }
    if !any {
        return Err(format!("invalid duration `{s}`"));
    }
    Ok(total)
}

/// Shape-checks an RFC 3339 timestamp with a mandatory offset. Seconds may
/// be omitted (6.md writes "2026-08-31T22:00Z"). Calendar validity beyond
/// cheap range checks is apply-time work.
pub fn validate_timestamp(s: &str) -> Result<(), String> {
    let b: Vec<char> = s.chars().collect();
    let fail = || {
        Err(format!(
            "invalid timestamp `{s}` — RFC 3339 with a mandatory offset, e.g. \"2026-08-31T22:00Z\" or \"...+02:00\""
        ))
    };
    let digit = |i: usize| i < b.len() && b[i].is_ascii_digit();
    let at = |i: usize, c: char| i < b.len() && b[i] == c;
    if !(0..4).all(digit) || !at(4, '-') || !digit(5) || !digit(6) || !at(7, '-') || !digit(8) || !digit(9) {
        return fail();
    }
    if !(at(10, 'T') || at(10, 't') || at(10, ' ')) {
        return fail();
    }
    if !digit(11) || !digit(12) || !at(13, ':') || !digit(14) || !digit(15) {
        return fail();
    }
    let val = |a: usize, n: usize| -> u32 { b[a..a + n].iter().collect::<String>().parse().unwrap_or(99) };
    if !(1..=12).contains(&val(5, 2)) || !(1..=31).contains(&val(8, 2)) || val(11, 2) > 23 || val(14, 2) > 59 {
        return fail();
    }
    let mut i = 16;
    if at(i, ':') {
        if !digit(i + 1) || !digit(i + 2) || val(i + 1, 2) > 60 {
            return fail();
        }
        i += 3;
        if at(i, '.') {
            i += 1;
            let start = i;
            while digit(i) {
                i += 1;
            }
            if i == start {
                return fail();
            }
        }
    }
    if at(i, 'Z') || at(i, 'z') {
        i += 1;
    } else if at(i, '+') || at(i, '-') {
        if !digit(i + 1) || !digit(i + 2) || !at(i + 3, ':') || !digit(i + 4) || !digit(i + 5) {
            return fail();
        }
        if val(i + 1, 2) > 23 || val(i + 4, 2) > 59 {
            return fail();
        }
        i += 6;
    } else {
        return fail();
    }
    if i != b.len() {
        return fail();
    }
    Ok(())
}
