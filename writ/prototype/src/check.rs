use std::collections::HashMap;

use crate::ast::*;
use crate::diag::{Error, Pos};

pub struct Checked {
    pub errors: Vec<Error>,
    pub warnings: Vec<Error>,
}

/// Well-formedness per 6.md (as amended by 7.md), minus the checks that
/// need writ's registries or inventory: unknown requirement/flag/notify
/// names, past `until` timestamps, and the inventory-aware lints are
/// apply-time work, not parser work.
pub fn check(file: &File) -> Checked {
    let mut c = Checker::default();
    c.run(file);
    Checked { errors: c.errors, warnings: c.warnings }
}

struct MacroInfo {
    kind: Kind,
    pos: Pos,
    used: bool,
}

#[derive(Default)]
struct Checker {
    macros: HashMap<String, MacroInfo>,
    errors: Vec<Error>,
    warnings: Vec<Error>,
}

impl Checker {
    fn err(&mut self, pos: Pos, msg: impl Into<String>) {
        self.errors.push(Error { pos, msg: msg.into() });
    }

    fn warn(&mut self, pos: Pos, msg: impl Into<String>) {
        self.warnings.push(Error { pos, msg: msg.into() });
    }

    fn run(&mut self, file: &File) {
        for item in &file.items {
            match item {
                Item::Macro(m) => {
                    // The body resolves against macros defined so far:
                    // define-before-use makes cycles (and self-reference)
                    // impossible by construction.
                    self.check_expr(&m.body, m.kind);
                    if let Some(prev) = self.macros.get(&m.name) {
                        let first = prev.pos;
                        self.err(m.pos, format!("macro `{}` redefined — first defined at {first}", m.name));
                    } else {
                        self.macros.insert(
                            m.name.clone(),
                            MacroInfo { kind: m.kind, pos: m.pos, used: false },
                        );
                    }
                }
                Item::Allow(r) => {
                    self.check_expr(&r.users, Kind::User);
                    self.check_expr(&r.accounts, Kind::Account);
                    self.check_expr(&r.hosts, Kind::Host);
                    self.check_clauses(&r.clauses);
                }
                Item::Deny(r) => {
                    self.check_expr(&r.users.expr, Kind::User);
                    self.check_expr(&r.accounts.expr, Kind::Account);
                    self.check_expr(&r.hosts.expr, Kind::Host);
                    self.check_clauses(&r.clauses);
                }
            }
        }
        let mut unused: Vec<(Pos, String)> = self
            .macros
            .iter()
            .filter(|(_, info)| !info.used)
            .map(|(name, info)| (info.pos, format!("macro `{name}` is defined but never referenced")))
            .collect();
        unused.sort();
        for (pos, msg) in unused {
            self.warn(pos, msg);
        }
    }

    fn check_expr(&mut self, expr: &Expr, kind: Kind) {
        // Duplicates the author wrote lint; duplicates arising from macro
        // expansion are ordinary composition and collapse silently (7.md).
        let mut seen: HashMap<String, Pos> = HashMap::new();
        for atom in &expr.atoms {
            self.check_atom(atom, kind);
            let key = atom_key(atom);
            if let Some(first) = seen.get(&key).copied() {
                self.warn(atom.pos(), format!("duplicate list entry — already listed at {first}"));
            } else {
                seen.insert(key, atom.pos());
            }
        }
    }

    fn check_atom(&mut self, atom: &Atom, kind: Kind) {
        match atom {
            Atom::MacroRef { name, pos } => {
                let mut msg = None;
                match self.macros.get_mut(name) {
                    None => msg = Some(format!("macro `${name}` referenced before definition")),
                    Some(info) => {
                        info.used = true;
                        if info.kind != kind {
                            msg = Some(format!(
                                "`${name}` is a {} macro, used in {} position",
                                kind_name(info.kind),
                                kind_name(kind)
                            ));
                        }
                    }
                }
                if let Some(m) = msg {
                    self.err(*pos, m);
                }
            }
            Atom::Labels { pairs, .. } => {
                let mut seen: HashMap<&str, Pos> = HashMap::new();
                for (k, _) in pairs {
                    if let Some(first) = seen.get(k.text.as_str()).copied() {
                        self.errors.push(Error {
                            pos: k.pos,
                            msg: format!("duplicate key `{}` in label selector — first at {first}", k.text),
                        });
                    } else {
                        seen.insert(&k.text, k.pos);
                    }
                }
            }
            _ => {}
        }
    }

    fn check_clauses(&mut self, clauses: &[Clause]) {
        let mut seen: HashMap<&'static str, Pos> = HashMap::new();
        for c in clauses {
            if let Some(first) = seen.get(c.keyword()).copied() {
                self.err(
                    c.pos(),
                    format!("duplicate `{}` clause — first at {first}; combine into one list", c.keyword()),
                );
            } else {
                seen.insert(c.keyword(), c.pos());
            }
        }
    }
}

/// A structural key for duplicate detection within one authored list.
fn atom_key(atom: &Atom) -> String {
    match atom {
        Atom::MacroRef { name, .. } => format!("$:{name}"),
        Atom::Tag { tag, value } => format!("t:{tag:?}:{}", value.text),
        Atom::Name(v) => format!("n:{}", v.text),
        Atom::Any(_) => "*".to_string(),
        Atom::Labels { pairs, .. } => {
            let mut ps: Vec<String> =
                pairs.iter().map(|(k, v)| format!("{}={}", k.text, v.text)).collect();
            ps.sort();
            format!("l:{}", ps.join(","))
        }
    }
}
