use std::process::ExitCode;

use writ_policy::ast::Item;

fn main() -> ExitCode {
    let mut path: Option<String> = None;
    let mut dump_ast = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--ast" => dump_ast = true,
            _ => path = Some(arg),
        }
    }
    let Some(path) = path else {
        eprintln!("usage: writ-policy [--ast] <policy-file>");
        return ExitCode::from(2);
    };
    let src = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::from(2);
        }
    };
    let (file, errors, warnings) = writ_policy::analyze(&src);
    for w in &warnings {
        eprintln!("{path}:{}:{}: warning: {}", w.pos.line, w.pos.col, w.msg);
    }
    for e in &errors {
        eprintln!("{path}:{}:{}: error: {}", e.pos.line, e.pos.col, e.msg);
    }
    if dump_ast {
        println!("{file:#?}");
    }
    if errors.is_empty() {
        let (macros, rules) = file.items.iter().fold((0, 0), |(m, r), i| match i {
            Item::Macro(_) => (m + 1, r),
            _ => (m, r + 1),
        });
        println!("ok: {macros} macro(s), {rules} rule(s), {} warning(s)", warnings.len());
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
