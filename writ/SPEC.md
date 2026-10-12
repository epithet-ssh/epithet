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

host  prod = {env:prod}
host  dev  = {env:dev}

# ── rules ───────────────────────────────────────────────
allow $sre -> ubuntu@$prod

allow $sre -> root@$prod, require [oncall, approval], label "sre-prod-root"

allow $eng -> *@$dev

allow $sec -> root@*, require mfa, notify "security-alerts", label "breakglass-root"

deny user{userType:contractor} -> *@$prod, label "no-contractors-in-prod"

deny !$infra -> *@$prod, when freeze, label "prod-freeze"
```

A file is a sequence of macro definitions and rules. A rule has a
punctuation **head** — who `->` account `@` where — and an optional
keyword **tail** of comma-separated clauses. The head carries the
dangerous part of the rule in a shape that cannot be silently
mis-grouped; the tail absorbs conditions and metadata.

The normative example set is `../pkg/writ/testdata/scenarios.writ`.
The retired Rust spike under `prototype/` records the earlier language;
the Go implementation and this specification define current behavior.

## 2. Model

The language matches against three entity kinds supplied by the surrounding
service. Writ consumes normalized facts; it does not query provisioning or
storage services.

**Users** are resolved and checked for eligibility by the directory provider.
The policy receives an eligible user or no user, never an `active` status.
Each user has a required canonical authentication `id`, a collection `name`,
optional presentation `userName`, flat `attributes`, and structured `groups`.
The ID must equal the identity authenticated by CA. Presentation uses `userName`
with ID fallback; name order does not affect certificate key IDs or audit identity.

**Groups** are membership objects, each with its own `name` collection, optional
`id`, and `attributes`. Static groups need no manufactured IDs. The built-in SCIM
adapter exposes each group's current `displayName` as its name and its
server-issued resource ID as `id`. Optional `externalId` is a separate attribute.
Same-name groups remain distinct objects. Renames and name reuse change name-based
matches immediately; ID-based rules continue to follow the selected resource.
There are no historical name bindings or reconciliation commands.

The built-in SCIM user adapter retains the normalized authentication identity as
user `id` (mapped from provisioning `externalId`), independently of the SCIM user
resource ID. Writ does not interpret OIDC or SCIM fields. Providers own mapping,
eligibility, membership resolution, and source-specific validation.

**Hosts** resolve through inventory to one resource with all equivalent
normalized hostnames in `name`, an optional provider `id`, and flat `attributes`.
Every hostname, including aliases, participates in the same host match. A deny
on one alias therefore applies through any other alias. Principal issuance
metadata is outside selectable attributes. Built-in inventory labels map to
attributes; exact records and ephemeral host patterns retain their existing
resolution behavior.

**Attributes** have string values, either single or multivalued. A predicate
compares one string against any value of that attribute. Missing, null, and empty
collections supply no values. An empty string is a value. Numbers, booleans,
objects, and collections with non-string members invalidate the facts and prevent
authorization. Keys are flat; no path traversal or implicit type conversion occurs.
Defined `name` and `id` fields cannot be shadowed in `attributes`.

**Accounts** are local login names filtered by the host's explicit `accounts`
field: null means unrestricted, an empty array permits none, and a list permits
only those names. The field must be present at the fact API boundary. Writ must
still allow the requested account. This filter does not claim to enumerate the
operating system's accounts.

**Breaking migration:** recompile source to IL schema 3. Older IL schemas and
selector unions are rejected. Replace `userName:alice` with `user:alice`, `id:X`
with `user{id:X}`, fixed user attributes with `user{department:engineering}`,
and host labels `{env=prod}` with `{env:prod}`. Express alternatives in separate
rules, reviewing deny semantics rather than mechanically splitting negation.
Rule content IDs change with the new representation. Static user `groups` now
contains objects, for example `groups: [{name: [ops]}]`. Fact HTTP responses use
`name`, `attributes`, and structured `groups`; see
[the provider contract](../docs/fact-services.md).

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

**Short selectors** use `user:` or `group:` immediately followed by a value.
They select the object's `name` attribute.

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

user-expr    = "$" ident | "*" | user-kind ":" value | user-kind filter ;
user-kind    = "user" | "group" ;
acct-expr    = "$" ident | name | "*" ;
host-expr    = "$" ident | "*" | filter | name [ filter ] ;
filter       = "{" [ predicate { "," predicate } [ "," ] ] "}" ;
predicate    = key ":" value ;

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

This EBNF and the Go implementation define current behavior. The Rust prototype
is historical. Selector lists and predicate-level negation are invalid. Bracketed
lists remain available for clauses such as `require [oncall, approval]`.
`*{...}` in host position is rejected; use the attribute-only `{...}` form.

## 5. Selectors and macros

Each position selects one object. Every predicate in its filter must match that
same object. For groups, one membership must satisfy the entire filter; attributes
from different groups cannot be combined. Repeated keys retain conjunction:
`group{role:admin, role:oncall}` needs one group containing both role values.
Identical repeated predicates are redundant. An empty filter matches any existing
candidate; `group{}` still needs a membership. `user{}` is equivalent to `*` in
user position, and `root@{}` is equivalent to `root@*`.

`user:alice` equals `user{name:alice}`; `group:ops` equals `group{name:ops}`.
In host position, `web{env:prod}` means `{name:web, env:prod}`. There is no host
kind marker: `root@host{env:prod}` requires the literal hostname `host`.
Multiple predicates narrow a match. Alternatives require separate rules.

Macros name one positive selector or another already-defined macro of the same
kind. A user macro may select a user or one of their groups. References cannot
extend filters or introduce unions, clauses, or negation:

```writ
user admins = group:ops
user deployers = $admins
host production = {env:prod}
allow $deployers -> deploy@$production
```

`!` is legal only on a whole user, account, or host selector in a **deny head**,
independently in each position. It complements the complete selector result,
after considering all group objects or host names. A missing attribute does not
match, so its whole-selector negation does match. Lookup failures and malformed
facts are errors, not missing attributes that can be negated.

Comparisons are byte-exact and case-sensitive, except host names are normalized
with ASCII lowercasing. User/group names and arbitrary attributes use equality.
Account names retain flat globs; host `name` predicates retain the label-aware
patterns from §3. Bare wildcards in other attribute values are rejected; quoted
wildcards are literal strings. Writ has no array, numeric, or boolean predicates.

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
3. Selector lists or predicate-level negation.
4. An allow-only clause (`require`, `until`, `ttl`) on a deny rule.
5. Macro referenced before definition.
6. Macro redefined (the diagnostic names the first definition).
7. Macro kind mismatch at a reference site.
8. `!` in a macro body.
9. A clause appearing more than once in one rule.
10. An object kind in an invalid position or extending a macro reference with a filter.
11. A bare `*` or `?` in an attribute-value position — a tag value, a
    label key, or a label value.
12. A trailing comma at bracket depth zero immediately before EOF.
13. An invalid timestamp (`until`) or duration (`ttl`) token.
14. *Apply-time:* unknown requirement, flag, or notify-target name —
    resolved against writ's registries.
15. *Apply-time:* an `until` timestamp already in the past.

### Warnings

1. A macro that is defined but never referenced.
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
   is eligible; the host resolves; the account satisfies the host's
   account filter. Any failure → 403.
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
  names, attribute keys and non-host-name values are untouched.
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

Schema 3 uses a single selector per position. A selector contains a kind and
an ordered list of attribute/value predicates, interpreted conjunctively:

```go
type Predicate struct { Attribute, Value string }
type Selector struct { Kind Kind; Predicates []Predicate }
type NegatableSelector struct { Not bool; Selector }
```

Allows contain plain selectors; denies contain negatable selectors. Negation
cannot be represented on an allow or an individual predicate. User positions
accept `user` or `group`; host positions accept `host`; account positions accept
`account` with at most one `name` predicate. All consumers validate schema and
selector kinds/positions before evaluating any rules.

Canonical selector JSON uses `kind` and `and`. An empty `and` array is an
unconstrained selector. A deny adds `not: true` only when negated. For example:

```json
{
  "effect": "allow",
  "users": {"kind":"group","and":[{"attribute":"name","value":"SRE"}]},
  "accounts": {"kind":"account","and":[{"attribute":"name","value":"root"}]},
  "hosts": {"kind":"host","and":[{"attribute":"env","value":"prod"}]},
  "require": ["oncall","approval"]
}
```

The universal source selector lowers to the position's kind with no predicates.
Repeated predicate keys remain a list, never a map that overwrites earlier values.

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
- Predicate lists, `require`, `when`, and `notify` are sorted and deduplicated
  in the hash projection. Conjunction is commutative and idempotent. Predicates
  sort by their canonical JSON encoding, preserving distinct values for one key.
  Empty selector `and` arrays remain explicit.

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
