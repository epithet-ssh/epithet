use writ_policy::analyze;
use writ_policy::ast::{Atom, Clause, File, Item, Tag};
use writ_policy::parser::{parse_duration, validate_timestamp};

static SCENARIOS: &str = include_str!("../examples/scenarios.writ");

fn errors(src: &str) -> Vec<String> {
    let (_, errors, _) = analyze(src);
    errors.iter().map(|e| e.msg.clone()).collect()
}

fn warnings(src: &str) -> Vec<String> {
    let (_, errors, warnings) = analyze(src);
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    warnings.iter().map(|w| w.msg.clone()).collect()
}

fn parse_ok(src: &str) -> File {
    let (file, errors, _) = analyze(src);
    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");
    file
}

#[track_caller]
fn assert_err(src: &str, needle: &str) {
    let es = errors(src);
    assert!(
        es.iter().any(|m| m.contains(needle)),
        "no error containing {needle:?} in {es:#?}"
    );
}

// ── the 6.md scenario corpus ────────────────────────────────────────

#[test]
fn scenario_file_parses_clean() {
    let (file, errors, warnings) = analyze(SCENARIOS);
    assert!(errors.is_empty(), "{errors:#?}");
    assert!(warnings.is_empty(), "{warnings:#?}");
    let (macros, rules) = file.items.iter().fold((0, 0), |(m, r), i| match i {
        Item::Macro(_) => (m + 1, r),
        _ => (m, r + 1),
    });
    assert_eq!(macros, 8);
    assert_eq!(rules, 10);
}

#[test]
fn simple_rule_shape() {
    let file = parse_ok("user sre = group:SRE\nallow $sre -> ubuntu@{env=prod}\n");
    assert_eq!(file.items.len(), 2);
    let Item::Allow(rule) = &file.items[1] else { panic!("expected allow rule") };
    assert!(matches!(&rule.users.atoms[..], [Atom::MacroRef { name, .. }] if name == "sre"));
    assert!(matches!(&rule.accounts.atoms[..], [Atom::Name(v)] if v.text == "ubuntu" && !v.quoted));
    let [Atom::Labels { pairs, .. }] = &rule.hosts.atoms[..] else { panic!("expected selector") };
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0.text, "env");
    assert_eq!(pairs[0].1.text, "prod");
}

#[test]
fn deny_negation_and_tags() {
    let file = parse_ok("user infra = group:Infrastructure\ndeny !$infra -> *@{env=prod}, when freeze\n");
    let Item::Deny(rule) = &file.items[1] else { panic!("expected deny rule") };
    assert!(rule.users.not);
    assert!(!rule.accounts.not);
    assert!(matches!(&rule.accounts.expr.atoms[..], [Atom::Any(_)]));
    assert!(matches!(&rule.clauses[..], [Clause::When { names, .. }] if names[0].text == "freeze"));
}

#[test]
fn star_is_legal_in_user_position() {
    let file = parse_ok("allow * -> ubuntu@{env=dev}\n");
    let Item::Allow(rule) = &file.items[0] else { panic!("expected allow rule") };
    assert!(matches!(&rule.users.atoms[..], [Atom::Any(_)]));
}

#[test]
fn tag_matcher_shape() {
    let file = parse_ok("allow id:\"carol@example.com\" -> postgres@db-1\n");
    let Item::Allow(rule) = &file.items[0] else { panic!("expected allow rule") };
    let [Atom::Tag { tag, value }] = &rule.users.atoms[..] else { panic!("expected tag") };
    assert_eq!(*tag, Tag::Id);
    assert_eq!(value.text, "carol@example.com");
    assert!(value.quoted);
}

// ── statement termination and continuation ──────────────────────────

#[test]
fn adjacent_rules_are_separate_statements() {
    let file = parse_ok("allow group:A -> a@b\nallow group:B -> c@d\n");
    assert_eq!(file.items.len(), 2);
}

#[test]
fn trailing_comma_continues_to_next_line() {
    let src = "allow id:\"carol@example.com\" -> postgres@prod-db-1,\n    require approval,\n    until \"2026-08-31T22:00Z\",\n    label \"carol\"\n";
    let file = parse_ok(src);
    assert_eq!(file.items.len(), 1);
    let Item::Allow(rule) = &file.items[0] else { panic!("expected allow rule") };
    assert_eq!(rule.clauses.len(), 3);
}

#[test]
fn comment_after_trailing_comma_still_continues() {
    let file = parse_ok("allow group:A -> root@h,  # gate below\n    require mfa\n");
    assert_eq!(file.items.len(), 1);
    let Item::Allow(rule) = &file.items[0] else { panic!("expected allow rule") };
    assert_eq!(rule.clauses.len(), 1);
}

#[test]
fn trailing_comma_at_eof_is_error() {
    assert!(!errors("allow group:A -> a@b,").is_empty());
}

#[test]
fn trailing_comma_inside_list_is_legal() {
    parse_ok("allow group:A -> [a, b,]@c\n");
}

#[test]
fn newlines_inside_brackets_are_whitespace() {
    parse_ok("allow group:A -> [\n  a,\n  b\n]@{\n  env=prod,\n}\n");
}

#[test]
fn arrow_munches_without_whitespace() {
    let file = parse_ok("user sre = group:SRE\nallow $sre->root@db-1\n");
    let Item::Allow(rule) = &file.items[1] else { panic!("expected allow rule") };
    assert!(matches!(&rule.accounts.atoms[..], [Atom::Name(v)] if v.text == "root"));
    assert!(matches!(&rule.hosts.atoms[..], [Atom::Name(v)] if v.text == "db-1"));
}

#[test]
fn empty_and_comment_only_files() {
    assert_eq!(parse_ok("").items.len(), 0);
    assert_eq!(parse_ok("# just a comment\n\n# another\n").items.len(), 0);
}

// ── negation restrictions ───────────────────────────────────────────

#[test]
fn negated_allow_is_rejected() {
    assert_err("!group:A -> root@h\n", "deny");
}

#[test]
fn negation_mid_allow_head_is_rejected() {
    assert_err("allow group:A -> !root@h\n", "only legal on deny");
}

#[test]
fn negation_inside_list_is_de_morgan_error() {
    assert_err("deny [!group:A, group:B] -> *@*\n", "whole expression");
}

#[test]
fn negation_in_macro_body_is_rejected() {
    assert_err("user notinfra = !group:Infrastructure\n", "macro bodies");
}

// ── deny-only clause restrictions ───────────────────────────────────

#[test]
fn require_on_deny_is_rejected() {
    assert_err("deny group:A -> *@*, require mfa\n", "not legal on a deny");
}

#[test]
fn until_on_deny_is_rejected() {
    assert_err("deny group:A -> *@*, until \"2026-08-31T22:00Z\"\n", "allow-only");
}

#[test]
fn ttl_on_deny_is_rejected() {
    assert_err("deny group:A -> *@*, ttl 5m\n", "allow-only");
}

// ── globs match names, never attribute values ───────────────────────

#[test]
fn glob_in_tag_value_is_rejected() {
    assert_err("allow group:SRE* -> root@h1\n", "never attribute values");
}

#[test]
fn glob_in_label_value_is_rejected() {
    assert_err("allow group:A -> root@{env=prod*}\n", "never attribute values");
}

#[test]
fn quoted_glob_is_a_literal() {
    parse_ok("allow group:\"weird*name\" -> root@h1\n");
}

#[test]
fn name_globs_stay_legal() {
    parse_ok("allow group:A -> ub*@db-?\n");
}

// ── well-formedness ─────────────────────────────────────────────────

#[test]
fn undefined_macro_is_error() {
    assert_err("allow $sre -> a@b\n", "referenced before definition");
}

#[test]
fn use_before_definition_is_error() {
    assert_err("allow $sre -> a@b\nuser sre = group:SRE\n", "referenced before definition");
}

#[test]
fn macro_redefinition_is_error() {
    assert_err("user x = group:A\nuser x = group:B\n", "redefined");
}

#[test]
fn macro_kind_mismatch_is_error() {
    assert_err("host prod = {env=prod}\nallow $prod -> a@b\n", "host macro, used in user position");
}

#[test]
fn keyword_macro_name_is_error() {
    assert_err("user deny = group:A\n", "keyword");
}

#[test]
fn duplicate_clause_is_error() {
    assert_err("allow group:A -> a@b, ttl 2m, ttl 3m\n", "duplicate `ttl`");
}

#[test]
fn duplicate_selector_key_is_error() {
    assert_err("allow group:A -> a@{env=prod, env=dev}\n", "duplicate key");
}

#[test]
fn unused_macro_warns() {
    let ws = warnings("user x = group:A\nallow group:B -> a@b\n");
    assert!(ws.iter().any(|w| w.contains("never referenced")), "{ws:#?}");
}

#[test]
fn duplicate_list_entry_warns() {
    let ws = warnings("allow group:A -> [a, a]@b\n");
    assert!(ws.iter().any(|w| w.contains("duplicate list entry")), "{ws:#?}");
}

// ── misc syntax errors ──────────────────────────────────────────────

#[test]
fn uppercase_keywords_do_not_lex() {
    assert!(!errors("DENY group:A -> *@*\n").is_empty());
}

#[test]
fn bare_word_cannot_start_a_rule() {
    assert!(!errors("carol -> a@b\n").is_empty());
}

#[test]
fn headless_rule_gets_migration_error() {
    assert_err("group:A -> a@b\n", "missing `allow`");
    assert_err("$sre -> a@b, ttl 2m\n", "missing `allow`");
    assert_err("* -> ubuntu@dev-1\n", "missing `allow`");
    assert_err("[group:A, group:B] -> a@b\n", "missing `allow`");
}

#[test]
fn allow_is_a_reserved_macro_name() {
    assert_err("user allow = group:A\n", "keyword");
}

#[test]
fn label_requires_quotes() {
    assert_err("allow group:A -> a@b, label foo\n", "quoted string");
}

#[test]
fn unterminated_string_is_error() {
    assert!(!errors("group:\"A -> a@b\n").is_empty());
}

#[test]
fn label_selector_outside_host_position_is_error() {
    assert!(!errors("{env=prod} -> a@b\n").is_empty());
}

// ── token validators ────────────────────────────────────────────────

#[test]
fn durations() {
    assert_eq!(parse_duration("2m"), Ok(120));
    assert_eq!(parse_duration("90s"), Ok(90));
    assert_eq!(parse_duration("1h30m"), Ok(5400));
    assert!(parse_duration("2").is_err());
    assert!(parse_duration("m").is_err());
    assert!(parse_duration("2d").is_err());
}

#[test]
fn timestamps() {
    assert!(validate_timestamp("2026-08-31T22:00Z").is_ok());
    assert!(validate_timestamp("2026-08-31T22:00:00+02:00").is_ok());
    assert!(validate_timestamp("2026-08-31T22:00:00.123Z").is_ok());
    assert!(validate_timestamp("2026-08-31T22:00").is_err()); // offset mandatory
    assert!(validate_timestamp("2026-13-01T00:00Z").is_err());
    assert!(validate_timestamp("not-a-time").is_err());
}
