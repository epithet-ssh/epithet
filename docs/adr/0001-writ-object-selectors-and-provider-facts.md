# ADR 0001: Evolve Writ toward object selectors and provider-defined facts

- Date: 2026-10-12
- Status: Accepted and implemented.
- Scope: Writ selectors and the policy fact model.

This records the decisions from the Writ and fact-service design discussion.
The implementation follows these decisions. The [Writ specification](../../writ/SPEC.md) defines the
language; this record preserves the reasons for the design choice.

## Context

The control-plane exploration aims to make fact providers independently
implementable, with optional management APIs discovered through OPTIONS and
Link headers. Freezing those APIs now would encode assumptions from our
built-in SCIM directory and inventory into a broader provider contract.

Writ currently exposes that coupling. User selectors have a fixed vocabulary
such as `userName:`, `id:`, and `department:`. Group membership is a list of
policy-visible names. Hosts have a separate `{key=value}` label syntax and
multiple equivalent hostnames. A provider can know facts that do not fit
those predefined user fields: an employment classification, for example,
or an AWS inventory's region and account information.

Group names expose another limitation. SCIM group `displayName` has no
uniqueness requirement. Distinct groups can have the same name.
[RFC 7643, group schema](https://www.rfc-editor.org/rfc/rfc7643.html#section-8.7.1) defines this explicitly.

The current directory compensates by binding a policy name to a particular
SCIM group. The binding survives renames and deletion; replacement groups
require explicit rebinding. That creates persistent state and administrative
reconciliation around historical ownership of names. The desired trust model
is simpler: trust the IdP's current names, including a resurrected name, while
allowing a policy author to distinguish one particular group when necessary.

Existing workflows are not requirements for this evolution. In particular,
preserving the SCIM alias/rebinding workflow is not a reason to retain it in
the future management API.

## Decision

### Select objects through a common filter form

Use the same object-filter construction for users, their group memberships,
and hosts:

```writ
allow user{employmentType:contractor, department:engineering} -> root@{environment:sandbox, region:eu-west-1}
allow group{id:abc123} -> root@{environment:production}
```

The object kind is explicit on the left and established by host position
after `@` on the right. The braces contain
attribute predicates, with `:` between an attribute and its required value.
The language defines matching behavior; providers supply the attributes.
An unfamiliar attribute is not a syntax error merely because the built-in
SCIM or inventory adapter does not supply it. This does not make malformed
syntax or invalid object kinds valid.

Use of these object kinds follows the rule positions: users and memberships
on the left, hosts after `@`. This decision does not introduce account objects,
arbitrary new object kinds, or a general expression language.

In host position, an attribute-only filter has no name constraint. A preceding
hostname contributes a `name` predicate, ANDed with the attributes:

| Form | Meaning |
|---|---|
| `root@*` or `root@{}` | Any resolved host |
| `root@{environment:production}` | A host with the specified environment |
| `root@web01{environment:production}` | Equivalent to `root@{name:web01, environment:production}` |

There is no special `host` kind marker in that position: `root@host{...}`
constrains the name to the literal hostname `host`. The spelling `root@*{...}`
is excluded because it adds no constraint beyond the attribute-only form.
This avoids both ambiguity between a kind marker and a hostname and redundant
spellings for the same filter.

### Conditions are AND on the same object

`{a:b, c:d}` requires both predicates to hold on one object. Adding a
predicate can only narrow the positive filter's match set.

Repeated attribute keys retain this AND meaning. For example,
`group{role:admin, role:oncall}` requires one group whose `role` values include
both `admin` and `oncall`. The predicates may match different values of that
attribute on the same object; neither predicate replaces the other. Repeating
an identical predicate does not change the match.

An empty filter `{}` is valid and accepts any object in its selector context.
It is the natural result of conjunction with no conditions, rather than a
special exception. Thus `root@{}` and `root@*` have the same meaning.
The filter still operates on resolved, eligible objects and does not bypass
identity resolution or account constraints. Likewise, `group{}` accepts any
group membership but still requires a membership to exist; an empty filter
does not create an object to match.

For example:

```writ
allow group{name:production-admins, source:corporate} -> root@*
```

The authenticated user must belong to a group satisfying both predicates.
Membership in one group named `production-admins` and another group whose
`source` is `corporate` is insufficient. Structured memberships preserve the
association between a group's identity, names, and other attributes.

Do not provide inline OR in filters or outer selector alternatives. Express
alternative grants as separate rules:

```writ
allow group:operators -> root@{environment:staging}
allow group:operators -> root@{environment:production}
```

This makes broadening a grant an explicit additional rule. It is a deliberate
change from the current selector unions, not just a new spelling for them.
Alternative values already present in a multivalued fact attribute remain
part of attribute matching; they are not an inline policy OR expression.

Deny precedence remains in force. Repeated allow rules are not a way to
override a deny. Splitting a negated union into several deny rules is not
generally equivalent; this decision does not define that transformation.

### Keep macros as aliases for one positive selector

A macro names a single positive selector, or references another macro of the
same declared kind. References are aliases; they add or combine no predicates.
For example:

```writ
user admins = group{name:admins, environment:production}
user deployers = $admins

allow $deployers -> root@*
```

Both macros belong in the user position. A host or account macro cannot
reference either of them. Retain the existing define-before-use and kind checks.
Macro bodies introduce neither alternatives nor negation, keeping the macro
layer within the same positive, single-selector model as the rule layer.

### Keep negation confined to deny selectors

Retain the existing negation boundary: `!` is legal only in deny rule heads,
where it negates an entire user, account, or host selector. Each position may
be negated independently. Allow rules and macro bodies remain purely positive;
a deny may negate a macro reference. Individual attribute predicates cannot
be negated inside a filter.

A missing attribute does not satisfy a predicate. Negating a selector that
does not match therefore matches, subject to the normal resolution and
eligibility gates. This can trigger a deny, never grant access. Keeping
negation off the allow path means a broader negated match removes access.

Missing attributes in valid facts are distinct from provider failure. A failed
lookup or malformed fact response is an error that prevents authorization,
not a non-match that can be negated into a successful match.

### Match one string value at a time

Selectable attribute values and predicate values are strings. Each predicate
uses string equality against one value. If a fact attribute is multivalued,
the predicate matches when any individual value equals the predicate's string.
This applies to all selectable attributes, not only `name`. Writ does not
introduce array literals or array comparisons; multiple predicates still AND
together on the same object.

There are no numeric or boolean predicate types or implicit conversions to
them. A numeric-looking identifier is a string. Numeric matching can be
considered later if a concrete user need arises; it does not justify adopting
JSON's numeric model or defining numeric equality now. This keeps the matching
model small while allowing providers to supply single or multiple string values.

At the fact API boundary, an omitted attribute, `null`, and an empty collection
all supply no values and cannot satisfy a predicate. An empty string is an
actual value and matches an explicitly empty string predicate. Numbers,
booleans, objects, and collections containing anything other than strings are
invalid selectable attribute values; they make the fact response invalid.
These rules concern selectable attributes, not operational fields such as
active-user eligibility.

Retain Writ's existing string rules: byte-exact, case-sensitive comparison,
double-quoted strings with quote and backslash escapes, and no implicit Unicode
normalization. Host `name` predicates retain the hostname-pattern behavior and
ASCII hostname normalization described below.

### Use flat attributes

Providers expose selectable attributes as a flat set of named values. Each
predicate key identifies one attribute directly; Writ does not traverse nested
objects or interpret keys as paths. Providers own the mapping from their source
data to attributes such as `department` or `region`. This keeps source structure
out of the matching language and avoids introducing a path or query language.

### The default attribute is always `name`

The short form selects `name`. These pairs have the same meaning:

| Short form | Explicit form |
|---|---|
| `user:alice` | `user{name:alice}` |
| `group:production-admins` | `group{name:production-admins}` |
| `root@web.example.com` | `root@{name:web.example.com}` |

The provider encodes its source-to-name mapping in the returned facts.
Writ does not discover or configure a different default attribute per provider.
A policy reader can always interpret the short form as selecting `name`.

For the built-in directory, user names ordinarily come from usernames, not
a person's display name, and group names come from group display names.
Host names are the resolved inventory hostnames, including their aliases.
An AWS instance's human label can be exposed as another attribute without
changing the meaning of a hostname.

### Names are multi-valued for every object kind

`name` is a collection even when it contains one value. A name predicate
matches if any name satisfies it. Conceptual fact fragments include:

```json
{"id": "subject-123", "name": ["alice", "alice@example.com"]}
```

```json
{"name": ["web.example.com", "web.internal"]}
```

These examples describe policy objects, not a finalized HTTP response schema.
Users commonly have one name, but the language does not require that.
Each name can select the same object; matching an alias does not authenticate
a different user or resolve a different host.

Keep user presentation independent of the selectable name collection. Retain
the explicit `userName` field for certificate key IDs, falling back to the
canonical user ID when it is absent. Audit identity remains the canonical user
ID. The first element of `name` has no special presentation meaning; reordering
names must not change certificate key IDs or audit identity.

Adding an alias is authorization-relevant. Adding `oncall` to a user's names
makes that user match `user:oncall`. Providers therefore own meaningful policy
facts, not cosmetic display metadata. Name matching does not imply names are
globally unique.

Host name matching retains the existing hostname-pattern behavior. The
complete name set is evaluated as one host; a deny must not be bypassable by
requesting another alias.

### Expose identity independently of names

Use `user{id:...}` and `group{id:...}` when a rule needs an identity rather
than whichever object currently bears a name. IDs are opaque and scoped to
the configured provider context. They should survive renames and must not be
reassigned to another identity. Do not derive an identity from a mutable name.

Users require a canonical ID to bind their facts to the authenticated OIDC
identity. Retain the existing meaning of normalized authentication identity;
do not reinterpret it as the SCIM server's resource ID.

Groups do not require an ID in the general fact model. A provider may supply
structured memberships with names and other attributes without manufacturing
IDs. Static groups therefore need no IDs derived from their names.

For SCIM groups, expose the SCIM resource's `id` as the group's `id` attribute
in the returned facts, selectable with `group{id:...}`. This is the same ID,
not a separate identifier. SCIM already requires the server to assign a stable,
non-reassignable resource ID, so this mapping adds no requirements for the
provisioning client. The adapter may also expose the optional `externalId` as
a separate attribute; it does not substitute for `id`.

| Provider change | Name selector | Identity selector |
|---|---|---|
| Another group has the same name | Can match members of either group | Matches only the selected identity |
| A group loses its old name on rename | Stops matching via that name | Continues matching that identity |
| A group is replaced with a new ID under the same name | Matches the replacement | Does not match the new identity |

This lets policy authors choose whether a rule follows current naming or a
particular identity. Name reuse no longer requires historical alias ownership
and manual reconciliation in Epithet. Exact identity remains available for
cases where same-named groups must be distinguished.

### Keep provider attributes extensible and operational facts explicit

Providers may return additional selectable attributes without adding a new
Writ matcher kind for each one. The built-in directory and inventory become
adapters to that model, rather than the source of its entire vocabulary.

This does not remove Epithet's operational contracts: authenticated identity
binding, user eligibility, hostname resolution, and account constraints still
need explicit validation. A provider-defined attribute cannot replace those
checks.

### Separate defined object fields from additional attributes

`name` is an explicit, multivalued field with Writ-defined semantics, not an
arbitrary entry in the additional attribute map. `id`, when supplied, is also
explicit. Both remain selectable through object predicates. Additional
provider attributes live in a flat `attributes` map and cannot replace these
defined fields.

A user fact contains the required authentication `id`, selectable `name`
collection, presentation `userName`, additional `attributes`, and structured
`groups`. Each group has its own `name`, optional `id`, and additional
`attributes`. For example:

```json
{
  "id": "oidc-subject-123",
  "name": ["alice", "alice@example.com"],
  "userName": "alice",
  "attributes": {"department": "engineering"},
  "groups": [
    {
      "id": "scim-group-456",
      "name": ["operators"],
      "attributes": {"externalId": "upstream-group-789"}
    }
  ]
}
```

The directory provider owns eligibility and returns an eligible user's facts
or no user. Authorization fact responses do not expose an `active` field.
SCIM active status remains inside the directory adapter; administration may
still inspect it. Matching operates only on the resolved, eligible user.

Host facts likewise expose the resolved hostnames through `name`, an optional
`id` when supplied by the provider, and additional `attributes`. The explicit
`accounts` field is an account filter, not a claim to enumerate operating-system
accounts. Retain its existing contract: `null` imposes no inventory account
restriction, `[]` permits no accounts, and a populated list restricts requests
to those account names. Omitting `accounts` remains invalid. Writ must still
authorize the requested account when this filter is unrestricted. Principal
issuance metadata remains separate from the selectable host attributes.

Providers own source-specific resolution and mapping. A SCIM adapter maps
current group display names and resource IDs; an LDAP adapter could resolve
directory memberships into the same shape. An EC2 adapter could expose resolved
DNS names alongside instance attributes and tags. These examples test the
provider boundary; they do not introduce LDAP or EC2 implementations, nested
group support, or new provider configuration in this change.

## Alternatives considered

| Alternative | Why it was not selected |
|---|---|
| Keep durable group aliases and explicit rebinding | Preserves historical name ownership at the cost of state and reconciliation the user does not want. |
| Require unique group names | Introduces a restriction SCIM does not promise and prevents legitimate same-named groups rather than making them distinguishable. |
| Expose only names as labels | Simple, but cannot express "this particular group" when names overlap. |
| Use only stable IDs in policy | Precise, but discards readable names and intentional name-following behavior. |
| Add `groupId:` and more predefined selectors | Handles one immediate case while retaining schema coupling and inconsistent user/host syntax. |
| Use standalone paths such as `user/department:engineering` | Identifies one attribute neatly, but makes combining predicates and preserving the same-object scope harder. |
| Fix the set of selectable attributes | Requires language changes for provider-specific facts such as region or employment classification. |
| Let providers declare the default selector attribute | Makes unchanged policy text depend on provider-specific selector configuration. Returning a common `name` attribute provides the needed mapping. |
| Allow inline OR | Makes an apparent refinement able to broaden a match. Repeated rules make alternatives explicit. |

Nested attribute paths are excluded from this version. Flat provider attributes
meet the selected scope without traversal or path-escaping rules.

## Consequences

The design removes knowledge of SCIM field layout and built-in inventory
labels from the core selector vocabulary. It moves source mapping into fact
providers and gives policy authors a consistent choice between names and IDs.
Structured groups keep identity and attributes together instead of exposing
parallel name and ID lists that lose their relationship.

The cost is a richer fact model and a smaller set of general matching rules
that must be defined precisely. Unknown attributes cannot all be diagnosed as
typos at compile time. More predicates narrow a positive match, but that alone
does not prove a policy safe: changing deny predicates, adding aliases, and
changing provider facts can change access.

The decision applies to both source policy and compiled IL, which is also
produced directly by tooling. Its consequences extend to matcher kinds,
selector unions, and rule content IDs, rather than being confined to source
syntax. This ADR does not select compatibility shims or a conversion tool.

Directory administration follows current group names as well. Remove
`directory groups bind`, list current names and SCIM IDs, and retain audit
inspection, including historical binding events. Existing administrator group
grants continue to select names; Writ does not become the administration engine.
New SQLite databases use schema version 2 without historical binding storage.
The application rejects other versions and performs no upgrades. For the current
single deployment, a disposable external tool handles the version 1 to 2
conversion transactionally, preserving resources, memberships, audit history,
and revision identity. Migration tooling is not checked into the repository;
selection of a supported migration framework remains deferred.

## Scope limits

This decision establishes the selector model and its meaning for names and
identities and the separation of authorization facts from provider internals.
It does not specify automatic legacy-union transformations. Management
operations and discovery schemas are also outside this decision.

## Related records

- [Writ evolution, YATL rv3znarg](../../.tasks/closed/rv3znarg.md) records the implementation and validation.
- [Deferred control-plane exploration, YATL s9cqey45](../../.tasks/open/s9cqey45.md),
  saved in jj change `vytpwlxu` (`42eed4b8`).
- [Earlier SCIM management follow-up, YATL 1c682zm5](../../.tasks/closed/1c682zm5.md).
  Its remaining historical binding workflow is superseded by this ADR.
- [Current Writ specification](../../writ/SPEC.md) and
  [fact-service documentation](../fact-services.md).
