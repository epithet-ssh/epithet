pub mod ast;
pub mod check;
pub mod diag;
pub mod parser;

use diag::Error;

/// Parse and well-formedness-check a policy source. Returns the AST (with
/// erroring statements dropped), errors, and warnings, each sorted by
/// position.
pub fn analyze(src: &str) -> (ast::File, Vec<Error>, Vec<Error>) {
    let (file, mut errors) = parser::parse(src);
    let checked = check::check(&file);
    errors.extend(checked.errors);
    let mut warnings = checked.warnings;
    errors.sort_by_key(|e| e.pos);
    warnings.sort_by_key(|e| e.pos);
    (file, errors, warnings)
}
