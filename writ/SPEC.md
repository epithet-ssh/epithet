# Writ policy language

Writ is the policy language for the epithet SSH certificate authority. A
writ policy decides, per connection request, whether a short-lived SSH
certificate is issued for one `(account, host)` destination, and under what
conditions. `account@host` is the authorization tuple and surface-language
head; it is not the literal SSH certificate principal.

This document is the specification: it states what the language is. The
design history — alternatives considered, arguments, and amendments —
lives in `ideas/` and is not restated here. Where this spec and an older
ideas document disagree, this spec wins. (Older documents call the
surface syntax "C′"; that name is retired. The language is writ, files
use the `.writ` extension.)

Two layers are specified here:

- **The surface language** — the human-authored text format.
- **The intermediate language (IL)** — the compiled rule format. The IL
  is writ's real policy interface; the surface language is one frontend
  over it. Grants are produced directly as IL by the CLI, and future
  producers (a web UI, tooling) target the IL, never the text.

## 1. A policy file

```
# ── vocabulary ──────────────────────────────────────────
user  sre   = group:SRE
user  eng   = group:Engineering
user  sec   = group:"Security Oncall"
user  infra = group:Infrastructure

host  prod = {env=prod}
host  dev  = {env=dev}

# ── rules ───────────────────────────────────────────────
allow $sre -> ubuntu@$prod

allow $sre -> root@$prod, require [oncall, approval], label "sre-prod-root"

allow $eng -> *@$dev

allow $sec -> root@*, require mfa, notify "security-alerts", label "breakglass-root"

deny type:contractor -> *@$prod, label "no-contractors-in-prod"

deny !$infra -> *@$prod, when freeze, label "prod-freeze"
```

A file is a sequence of macro definitions and rules. A rule has a
punctuation **head** — who `->` account `@` where — and an optional
keyword **tail** of comma-separated clauses. The head carries the
dangerous part of the rule in a shape that cannot be silently
mis-grouped; the tail absorbs conditions and metadata.

The normative example set is `prototype/examples/scenarios.writ`.

## 2. Model

The language matches against three entity kinds. Writ owns or mirrors
all three inventories, which is what makes inventory-aware linting
possible.

**Users** arrive via SCIM (RFC 7643); writ never edits them. Policy can
match exactly:

| Matcher | SCIM source |
|---|---|
| `id:"..."` | The configured identity attribute (default `userName`) |
| `group:...` | Group `displayName` |
| `type:...` | `userType` |
| `dept:...` | Enterprise extension `department` |
| `org:...` | Enterprise extension `organization` |

Identity is an **opaque string**: one configured OIDC claim is compared
byte-for-byte against one configured SCIM attribute. Writ never parses
the value; it is often email-shaped but never email-semantic. A user
with `active=false`, or with no SCIM match, matches nothing — this is a
structural gate no policy text can express or bypass.

A policy reference to a duplicated group `displayName` matches the
union; sync warns loudly and points at the IdP as the thing to fix.

**Hosts** resolve through the configured inventory. A resolved authorization
resource has a unique `name`, a `map[string]string` of labels (k8s-style), and
an optional list of local account names. An inventory implementation may carry
other host data, but Writ does not observe it. The static inventory supports
exact host entries and ordered name patterns for ephemeral fleets. When hosts
share a destination-bound principal domain, inventory exposes the domain name
as the resource name so policy cannot imply per-member isolation that SSH does
not enforce. Policy matches resolved resources by name (globs allowed), or by
label selector `{k=v, ...}` (entries AND).

**Accounts** are byte-exact local login names. If a resolved host supplies an
account list, matching is **inventory-grounded**: the requested account must
be present, and even `*` or a glob cannot bypass the list. If the account list
is absent, rules match the requested account name directly. Account existence
is ultimately enforced by the target host's login system, not by Writ.

Writ stops at the authorization decision for the human-readable
`(identity, account, host)` tuple. It does not define SSH certificate principal
encoding, host identity enrollment, or key-rotation protocols. Those belong
to the policy server and its surrounding control plane and cannot be changed
by policy text.

**Requirements** (`require`) are named async facts — `oncall`, `mfa`,
`approval` — resolved by registered handlers. A name in policy is a
configured instance: handler binary plus static config, bound to the
name in writ's registry. The grammar takes names only; parameters live
at registration. Handlers resolve to `satisfied`, `unsatisfied`, or
`pending`, and declare latency class (`fast` | `human`) and
side-effect-ness at registration.

**Flags** (`when`) are named booleans in writ's own projected state, set
and cleared via API/CLI (`freeze`, `lockdown`). Synchronous and
two-state: known at evaluation time, never pending.

**Notify targets** are registered instances, like requirement handlers.
The registration declares which events the target wants via an `on` set
(default `["issued", "denied"]`); the grammar takes the name only.

**Grants** are time-boxed individual permissions created via CLI/API
(`writ grant ...`), never by editing policy text. A grant is an
IL-native allow rule carrying an absolute `until`, unioned with the
authored rule set at evaluation. Relative TTLs belong to grants (where
creation time is an event fact); authored rules use absolute `until`
timestamps for planned temporary policy.

## 3. Lexical structure

Files are UTF-8.

**Whitespace** is space and tab. **Newlines are significant**: after
comments are stripped, a newline terminates the statement when bracket
depth is zero and the previous significant token is not a comma. EOF
terminates the last statement. There is no `\` continuation — an open
`[` or `{`, or a trailing comma, is the continuation signal.

**Comments** run from `#` to end of line and are not recognized inside
strings. There are no block comments. Because comments are stripped
before the newline test, a comment after a trailing comma still
continues the statement.

**Bare words** are runs of `[A-Za-z0-9_.*?/]` and interior hyphens: a
bare word may contain `-` but may not begin or end with one. (RFC 1123
already forbids hostnames ending in `-`; the restriction is what lets
`$sre->root` lex without whitespace.) `@` and `:` are excluded from
bare words: an unquoted `@` occurs in exactly one place per rule (the
head's `account@host` separator), and `:` is the tag separator.

**Strings** are double-quoted with exactly two escapes, `\"` and `\\`.
No newlines inside strings; UTF-8 passes through literally; there are no
`\u` escapes. Quotes are permitted anywhere a bare word is, and required
for any value the bare-word charset cannot carry (spaces, `@`, `:`,
leading/trailing `-`, the empty string).

**Keywords** — `allow`, `deny`, `user`, `host`, `account`, `require`,
`when`, `until`, `ttl`, `notify`, `label` — are lowercase-only and
reserved as macro identifiers, nothing more. They are recognized
positionally: statement keywords at statement start, clause keywords
after a depth-0 comma. Values never occur in those positions, so no
other reservation is needed. (`DENY` lexes as a bare word, and a bare
word at statement start is a parse error.)

**Macro identifiers** match `[A-Za-z_][A-Za-z0-9_-]*`, not ending in
`-`. `$` is its own token, followed by an identifier; `$foo.bar` is a
diagnosable error rather than a silent short match.

**Tags** are the five user-matcher prefixes `id`, `group`, `type`,
`dept`, `org`, each immediately followed by `:`.

**Timestamps** are ordinary quoted strings, validated after parsing as
RFC 3339 with a mandatory offset or `Z`: `until "2026-08-31T22:00Z"`. A
policy file must not mean different things on different machines.

**Durations** are ordinary bare words, validated after parsing: integer
plus `s` / `m` / `h`, composable (`2m`, `90s`, `1h30m`). They occur only
after `ttl`.

**Globs** match the complete name. Account globs are flat: `*` matches any run
of characters and `?` matches one character. Host globs are label-aware: `*`
and `?` never cross `.`, while `**` is legal only as a complete dot-delimited
label and matches zero or more labels. Thus `*.controlplane.internal` matches
`api.controlplane.internal` but not `blue.api.controlplane.internal`, while
`**.controlplane.internal` matches both and also `controlplane.internal`.
A standalone `*` is the universal matcher, not a glob. Character classes,
brace alternatives, escapes, `/`, malformed star runs, and embedded `**` are
errors in host patterns.

**Trailing commas** are legal inside `[]` and `{}`. At bracket depth
zero a trailing comma drives continuation, so one immediately before EOF
promises a clause that never arrives and is an error.

## 4. Grammar

Every statement begins with one of the five statement keywords:
`user` / `host` / `account` introduce macro definitions, `allow` /
`deny` introduce rules. The grammar is LL(1) at statement start.

```ebnf
file         = { statement } ;
statement    = ( macro-def | rule ) TERM ;

macro-def    = "user"    ident "=" user-expr
             | "host"    ident "=" host-expr
             | "account" ident "=" acct-expr ;

rule         = allow-rule | deny-rule ;
allow-rule   = "allow" user-expr "->" acct-expr "@" host-expr
               { "," allow-clause } ;
deny-rule    = "deny" [ "!" ] user-expr "->" [ "!" ] acct-expr
               "@" [ "!" ] host-expr { "," deny-clause } ;

allow-clause = "require" name-list
             | "when"    name-list
             | "until"   timestamp
             | "ttl"     duration
             | "notify"  string-list
             | "label"   string ;

deny-clause  = "when"    name-list
             | "notify"  string-list
             | "label"   string ;

user-expr    = user-atom | "[" user-atom { "," user-atom } [ "," ] "]" ;
user-atom    = "$" ident | tag ":" value | "*" ;
tag          = "id" | "group" | "type" | "dept" | "org" ;

acct-expr    = acct-atom | "[" acct-atom { "," acct-atom } [ "," ] "]" ;
acct-atom    = "$" ident | name | "*" ;

host-expr    = host-atom | "[" host-atom { "," host-atom } [ "," ] "]" ;
host-atom    = "$" ident | label-sel | name | "*" ;
label-sel    = "{" label-eq { "," label-eq } [ "," ] "}" ;
label-eq     = key "=" value ;

name-list    = name | "[" name { "," name } [ "," ] "]" ;
string-list  = string | "[" string { "," string } [ "," ] "]" ;

name         = bare | string ;
value        = bare | string ;
key          = bare | string ;
```

`TERM` is the statement terminator defined lexically in §3. `timestamp`
and `duration` are ordinary `string` and `bare` tokens with post-parse
validation, not lexer modes. Newlines are permitted freely inside `[]`
and `{}`.

This EBNF is normative. `prototype/src/grammar.pest` is the reference
implementation; it additionally parses several *forbidden* forms as
"poison" productions so they can be rejected with pointed diagnostics
instead of a generic expectation list (a negated allow head, a headless
rule, an allow-only clause on a deny, `!` on a list atom).

Notes:

- **Singleton lists may omit brackets.** `require approval` ≡
  `require [approval]`.
- **`[]` is always a list; `{}` is always a label selector.** Each sigil
  has exactly one meaning. `[]` reads as union in match positions and as
  conjunction in `require`/`when` — a deliberate asymmetry English also
  carries ("as ubuntu or deploy"; "require oncall and approval").
- **`{}` entries AND**; union of selectors is a list of selectors.
- **`*` is legal in every match position**, including user position
  (visible and intentional, where `!` on an allow would be neither).

### Rules with an inferred effect are gone

An earlier revision of the language inferred `allow` from a rule with no
keyword. Every rule now leads with `allow` or `deny`. A headless rule is
rejected with a migration message.

## 5. Match expressions and macros

A match expression denotes a **set of matchers** — order carries no
meaning and duplicates collapse. `[a, b]` matches anything `a` or `b`
matches.

**Macros** bind a name to a match expression of a declared kind:

```
user    sre        = group:SRE
host    staging_db = {env=staging, role=db}
account admin      = [root, postgres]
```

- A macro is a named disjunction of matchers, not text. `$sre` in a rule
  is a splice, not a substitution — and splices **flatten**: with
  `user sre = [group:SRE, group:Infra]`, the expression `[$sre, group:X]`
  is a three-element set, not a nested one.
- Kind is declared, never inferred, and checked at every reference site.
- Composition is **union only**: a macro body may reference same-kind
  macros inside a `[]` list, nothing else. No intersection, no
  refinement.
- **Define before use.** Cycles are impossible by construction.
  Redefinition is an error, not last-wins.
- **Macro bodies are purely positive**: `!` in a macro body is an error.
  The macro layer must not express anything the rule layer forbids.
- There are no macros for tail clauses. Whatever the macro layer does,
  it must never hide what a rule requires.

**Negation** (`!`) exists only in `deny` heads, applies to a whole
position's expression (never an atom inside a list), and is legal in all
three positions independently. `![$a, $b]` means "in neither"; `[!$a,
!$b]` is an error (the De Morgan footgun — it would mean "everyone"). A
negated allow is a syntax error. The reason is drift: a negated set
*grows* as the world grows, which is fail-safe on a deny and fail-open
on an allow.

**Globs match names, never attribute values.** Account names and host
names may glob; a standalone `*` is legal anywhere and means every value in
that position. Tag values
(`group:`, `id:`, …), label keys, and label values are exact. A bare `*`
or `?` in an attribute-value position is an error; a **quoted attribute
value is always a literal** (`group:"weird*name"` matches a group with a
star in its name). The grouping that value-globs would provide belongs
in a macro (`user infra = [group:infra-core, group:infra-net]`), where
it is visible in review and lintable against the inventory.

**Comparison is byte-exact everywhere.** No matcher carries a
case-sensitivity mode. The one normalization: host names are
**ASCII-lowercased** (`A-Z` → `a-z` only — not Unicode folding, which is
locale- and version-dependent) at three ingress boundaries —
registration, request resolution, and policy compilation — so the
matcher itself stays a byte compare. Hosts get this because a host name
is a lookup key into writ's own namespace arriving from three directions
that disagree about case; an account name, by contrast, is a value writ
signs into the certificate, and folding it would issue certs for
principals that do not exist.

## 6. Clauses

Clause order within a rule is free (the formatter canonicalizes it).
Each clause may appear at most once; use a list for multiple values.

| Clause | On | Value | Meaning |
|---|---|---|---|
| `require` | allow | requirement names | All named facts must be satisfied; unmet facts can pend (202). Only ever withholds. |
| `when` | allow, deny | flag names | All named flags must currently hold, else the rule does not match. Synchronous; never pends. |
| `until` | allow | timestamp | Rule stops matching at the given instant. |
| `ttl` | allow | duration | Overrides the deployment-default cert TTL for this rule. |
| `notify` | allow, deny | target names | Fire-and-forget notification when the rule fires; never gates the decision. |
| `label` | allow, deny | string | Human-readable alias for the rule. Optional everywhere, cosmetic only (§10). |

`require`, `until`, and `ttl` are allow-only by construction. On a deny,
a failed condition drops the deny out — more access — so each condition
on a deny must be sound when false. `when` qualifies (a flag is local
two-state state; there is nothing to fail open through). `require`
(async, three-state) and `until` (a scheduled loosening with no human in
the loop) do not.

`notify` on a deny is legal; only the `denied` event is meaningful
there, and a target whose registered `on` set cannot fire on the rule is
dead configuration and lints as such.

## 7. Static checks

### Errors

Reported at parse/compile time unless marked *apply-time* (those need
writ's registries and inventory):

1. A statement that is neither a macro definition nor an
   `allow`/`deny` rule — including the retired headless-rule form, which
   gets a migration message.
2. `!` anywhere in an allow rule.
3. `!` on an atom inside a list rather than on the whole expression.
   The diagnostic says "negation applies to the whole expression:
   `![$a, $b]`", not "unexpected `!`".
4. An allow-only clause (`require`, `until`, `ttl`) on a deny rule.
5. Macro referenced before definition.
6. Macro redefined (the diagnostic names the first definition).
7. Macro kind mismatch at a reference site.
8. `!` in a macro body.
9. A clause appearing more than once in one rule.
10. Duplicate key within one `{}` selector.
11. A bare `*` or `?` in an attribute-value position — a tag value, a
    label key, or a label value.
12. A trailing comma at bracket depth zero immediately before EOF.
13. An invalid timestamp (`until`) or duration (`ttl`) token.
14. *Apply-time:* unknown requirement, flag, or notify-target name —
    resolved against writ's registries.
15. *Apply-time:* an `until` timestamp already in the past.

### Warnings

1. A macro that is defined but never referenced.
2. A duplicate atom within one *authored* list. (Duplicates arising from
   macro expansion are ordinary composition and collapse silently.)
3. Two rules with identical content ids (§11) — usually an unfinished
   copy-paste. The warning names both source lines; apply proceeds and
   the rules collapse to one.
4. *Apply-time:* a notify target whose registered `on` set makes it dead
   on this rule (e.g. `["issued"]` on a deny).
5. *Apply-time:* a `{}` selector matching no currently registered host,
   or a `group:` matching no synced SCIM group — the inventory-aware
   lint only a policy server that owns the inventory can do.

Warnings never block apply. Note what is *not* warned: absence of a
`label` is not a defect — labels are cosmetic and every rule has a
canonical rendering derivable from its IL on demand.

## 8. Evaluation

Evaluation is **order-independent**: file order never matters. For a
request `(user, host, account)`:

1. **Structural gates.** The user resolves via the identity binding and
   is `active`; the host is registered; the account is in the host's
   reported inventory. Any failure → 403.
2. **Collect matching rules** — authored rules plus unexpired grants. A
   rule matches when its user, account, and host expressions all match.
3. **Deny wins.** Any matching deny whose `when` flags (if any)
   currently hold → 403. Always. No allow can override.
4. **Allow, sync conditions.** Matching allows whose `when` or `until`
   conditions fail drop out — non-matches, not pending.
5. **Allow, async requirements.** Surviving allows resolve their
   `require` facts through the three-state resolver. If any single allow
   has all requirements satisfied → **200**, issue.
6. **Pending.** Else, if any surviving allow has requirements unstarted
   or pending → **202** with `retryAfter` and a message naming what is
   being waited on.
7. Else → **403**.

**Cross-rule laziness.** Fast facts for all surviving allows resolve
first; human-latency, side-effecting facts (`approval`) are triggered
only for allows whose fast requirements have all settled true. An
approval request is created only when it is the last thing standing
between the user and a cert.

**Fail closed.** Evaluator errors (handler crash, timeout past
deadline) → 500, never "treat as non-match".

**TTL combines by minimum.** When several satisfied allows specify
`ttl`, the shortest governs; absent any, the deployment default applies.
Minimum keeps composition fail-safe — under maximum, appending a broad
rule would silently lengthen the certs of a deliberately tight one.
(Sessions outlive certs in epithet, so a short TTL costs re-issuance
latency, not dropped sessions.)

**Notify** fires per the target's registered `on` set. Pending (202) is
not in the default set; a target that opts in owes the dedup story.

The language is monotone by construction: `require` can only withhold,
deny always wins, negation cannot reach the allow path, unresolved facts
cannot unlock. Adding a rule never increases access beyond what that
rule itself grants.

## 9. Formatting

`writ policy fmt` is normative; the LSP formats on save. Formatting is
idempotent, is a pure function of the parsed file, and **never changes
the compiled IL** — the test suite asserts this directly.

- Macro block first, then rules. Kind keywords and `=` align within a
  run of adjacent macro definitions; a blank line breaks the group.
- One rule per line when it fits in 80 columns; otherwise the head on
  the first line and one clause per continuation line, indented four
  spaces.
- Canonical clause order: `require`, `when`, `until`, `ttl`, `notify`,
  `label` — gates first, identity last.
- **Quoting is a rendering decision, not stored state.** The formatter
  emits quotes iff the bare rendering would not lex back to the same
  value *in that position*, and strips them otherwise. (Bare-legality is
  position-dependent: `weird*name` is bare-lexable but illegal as an
  attribute value, so `group:"weird*name"` keeps its quotes while a host
  glob does not. Timestamps keep quotes as a consequence, not an
  exception.) On input that parses but fails well-formedness, `fmt`
  renders tokens as authored and never synthesizes the quotes that would
  make error 11 disappear — a formatter that silently repairs an
  ill-formed security policy is worse than one that leaves it ugly.
- Host names and host-position globs are ASCII-lowercased. Account
  names, label keys and values, and tag values are untouched.
- Singleton lists unbracketed. One space after commas inside `[]` and
  `{}`, none before. Lists are never reordered and never emitted with a
  trailing comma.
- Comments and blank-line grouping preserved; blank runs collapse to
  one.

## 10. The intermediate language

The IL is a **set of rules keyed by content id** (§11). Macros are
expanded at compile time; nothing downstream of the compiler knows they
existed. Compilation is deterministic, so the IL stored in a
`PolicyUpdated` event is reproducible from the stored source. The IL
carries a schema version from day one; it outlives any surface-syntax
revision by design.

The IL is defined abstractly by this section — its shapes and
invariants, not any encoding. An implementation holds it in native types
(the structs of whatever language writ is written in); the canonical
JSON of §11 is the interchange and hash encoding, used wherever IL
crosses a process or language boundary. The JSON below illustrates
shapes.

An allow rule:

```json
{
  "schema":   1,
  "id":       "a3f9c1d2e8b4",
  "effect":   "allow",
  "label":    "sre-prod-root",
  "users":    {"or": [{"group": "SRE"}]},
  "accounts": {"or": [{"name": "root"}]},
  "hosts":    {"or": [{"labels": {"env": "prod"}}]},
  "require":  ["oncall", "approval"]
}
```

A deny rule — `not` sits on the whole expression, never on a matcher:

```json
{
  "schema":   1,
  "id":       "7c1e0b93a5df",
  "effect":   "deny",
  "label":    "prod-freeze",
  "users":    {"not": true, "or": [{"group": "Infrastructure"}]},
  "accounts": {"or": [{"any": true}]},
  "hosts":    {"or": [{"labels": {"env": "prod"}}]},
  "when":     ["freeze"]
}
```

**Negation is a type distinction, not a validated field.** Allow rules
carry a plain match set in all three positions; deny rules carry a
negatable match set (the same set plus a `not` bit):

```go
type MatchSet struct { Or []Matcher }

type NegatableMatchSet struct {
    Not bool
    MatchSet
}
```

A negated allow has no field to set — unrepresentable rather than
rejected, so every IL producer (compiler, grants CLI, future UI) gets
the restriction structurally, and no validator has to stay correct
forever. A per-matcher negation flag is rejected outright: it could
express the `[!$a, !$b]` footgun the grammar forbids.

### Matcher taxonomy

| Position | Kinds |
|---|---|
| `users` | `{"id": s}` `{"group": s}` `{"type": s}` `{"dept": s}` `{"org": s}` `{"any": true}` |
| `accounts` | `{"name": s}` `{"glob": s}` `{"any": true}` |
| `hosts` | `{"name": s}` `{"glob": s}` `{"labels": {k: v}}` `{"any": true}` |

All literal string values compare byte-exact. Account `glob` supports flat
`*` and `?`; host `glob` uses the label-aware syntax defined in section 3.
Host `name` and `glob` values are stored ASCII-lowercased. A standalone
`*`, quoted or bare, compiles to `{"any": true}` in every position, never to
`{"glob": "*"}` — it is semantically distinct, skips the glob engine,
and gives the "grants to everyone" lint a token to recognize.

Allow-only clauses (`require`, `until`, `ttl`) exist only on the allow
shape. `until` is stored as an absolute RFC 3339 UTC instant; `ttl` as
integer seconds.

## 11. Content identity

Every compiled rule carries a stable, content-derived id:

> `id = sha256(canonical-projection)` — full digest stored, displayed as
> 12 lowercase hex characters, and the CLI accepts any unambiguous
> prefix. The git model.

The **canonical projection** is computed for hashing only; the stored IL
preserves authored order:

- `schema`, `id`, and `label` are dropped. Everything else is in —
  `effect`, all three matcher positions, `require`, `when`, `until`,
  `ttl`, `notify`. (`label` is an alias *over* the id; hashing it would
  be circular and renames would orphan audit history. `notify` is in
  because it changes what the system does. `schema` is out so a schema
  bump does not churn every id in every deployment.)
- Canonical JSON: object keys sorted, no insignificant whitespace, empty
  and null fields omitted, `ttl` as integer seconds, timestamps RFC 3339
  UTC with `Z`.
- **Every list is sorted and deduplicated** — match sets, `require`,
  `when`, `notify`. Lists are sets, and union and conjunction are both
  commutative and idempotent, so the sort is semantics-preserving;
  `[$sre, $dba]` and `[$dba, $sre]` are correctly one rule. Matchers
  sort bytewise by their own canonical encoding.

Consequences:

- Reformatting, macro renames, list reordering, and label edits never
  change an id. Any semantic edit does — an edited rule getting a new id
  is correct; it is a different rule.
- **IL equality is canonical, not structural.** Two rules equal as sets
  may differ as structs; nothing may compare rules with deep equality.
- Two rules with the same id are duplicates: apply warns (naming both
  source lines) and collapses them, keeping the first label in source
  order. Labels are cosmetic, so the collapse loses nothing.
- Grants hash like any other rule; since a grant's absolute `until` is
  in the hash, repeat grants of the same access get distinct ids
  naturally. Grants get no synthetic labels — a 202 message names the
  *requirement* being waited on, and a grant's display handle derives
  from its own fields at render time.

## 12. Open questions

Carried out of the design sessions, unresolved as of this writing (see
`ideas/7.md` for detail):

1. Dry-run: `writ policy test` needs a no-side-effects evaluation mode.
2. Whether to commit to keeping the IL trivially Datalog-clause-shaped
   so a reverse-query backend ("who can reach root on prod-db-1?")
   stays cheap.
3. Requirement-handler packaging: Lua-in-writ runtime vs. plain
   subprocesses, and a contrib set of common handlers.
4. `*` in user position — legal today because it is visible and
   intentional, but it is the one matcher that grants to everyone
   including future users.
5. Name-resolution timing when a handler or notify target is
   deregistered while policy still names it.
6. Prefix-ambiguity scope for content ids: unique within the current
   policy version, or across all event-log history?
7. Grant amendment: extending a grant's `until` yields a new id; the
   revocation and audit story should say how the two are linked.
8. Whether logs render the authored form (`$sre`) or the expanded IL
   disjunction, or both.
9. A single chokepoint type for host-name lowercasing rather than three
   call sites.
10. Rule-local carve-outs. "All of ENG except interns, for this rule
    only" is currently encoded as an allow/deny pair, which is a global
    exclusion and couples two unlinked rules (mitigation: share scope
    via macros; keep the deny broad). Deferred design: an `except`
    operator — set difference with a mandatory positive base, compiling
    to a `Difference{Base, Minus}` IL matcher — which is bounded under
    IdP drift and keeps negation unconstructible on the allow path. `!`
    stays deny-only regardless.
11. A static profile. Epithet's built-in static policy server adopts
    the writ language. Writ is implemented in Go, and the frontend
    (lexer, parser, checker, lowering, IL types, fmt) lives in a
    standalone language module with no server code, imported by both
    the epithet static server and the writ server — neither product
    depends on the other; both depend on the language. (The Rust
    `prototype/` is a retired spike; its pest grammar and tests are the
    porting reference. The tree-sitter grammar remains the independent
    second implementation keeping the grammar honest.) The static
    profile pairs policy with a static inventory file standing in for
    the SCIM store and host registry — the same shapes with file
    provenance. To settle: the inventory file format; which clauses the
    profile rejects (`require` / `when` / `notify` name registries the
    static server lacks); and how account grounding behaves when the
    inventory file omits account lists.
