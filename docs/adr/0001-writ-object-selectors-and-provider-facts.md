# ADR 0001: Evolve Writ toward object selectors and provider-defined facts

- Date: 2026-10-12
- Status: Accepted design direction.
- Scope: Writ selectors and the policy fact model.

This records the decisions from the Writ and fact-service design discussion.
It describes intended behavior, not functionality available in the current
parser or fact APIs. The [Writ specification](../../writ/SPEC.md) defines the
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
Alternative values already present in a fact's `name` collection remain
part of name matching; they are not an inline policy OR expression.

Deny precedence remains in force. Repeated allow rules are not a way to
override a deny. Splitting a negated union into several deny rules is not
generally equivalent; this decision does not define that transformation.

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

Adding an alias is authorization-relevant. Adding `oncall` to a user's names
makes that user match `user:oncall`. Providers therefore own meaningful policy
facts, not cosmetic display metadata. Name matching does not imply names are
globally unique.

Host name matching retains the existing hostname-pattern behavior. The
complete name set is evaluated as one host; a deny must not be bypassable by
requesting another alias. This decision does not define every equality,
quoting, or normalization rule for the expanded model.

### Expose identity independently of names

Use `user{id:...}` and `group{id:...}` when a rule needs an identity rather
than whichever object currently bears a name. IDs are opaque and scoped to
the configured provider context. They should survive renames and must not be
reassigned to another identity. Do not derive an identity from a mutable name.

For users, retain the existing meaning of normalized authentication identity.
Do not reinterpret it as the SCIM server's resource ID. The exact choice and
lifecycle of group identity, including its SCIM mapping, remain open.

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
binding, active-user eligibility, hostname resolution, and account constraints
still need explicit validation. A provider-defined
attribute cannot replace those checks. The representation separating those
required facts from additional policy attributes is not settled here.

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

Path notation may still be useful inside filters for nested attributes. That
possibility is retained for discussion, not adopted as a JSON Pointer contract.

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

Removing group bindings also affects directory administration, which currently
uses the bound group names. The distinction between names and identities matters
there too; this ADR does not make Writ the administration policy engine.

## Scope limits

This decision establishes the selector model and its meaning for names and
identities. It does not specify the complete wire representation, group ID
provenance, a general value or path type system, missing-value behavior under
negation, or macro and legacy-union transformations. Those details are not
implicitly decided by the examples. Management operations and discovery
schemas are also outside this decision.

## Related records

- [Writ evolution, YATL rv3znarg](../../.tasks/open/rv3znarg.md) tracks open
  design work, sequencing, and implementation planning.
- [Deferred control-plane exploration, YATL s9cqey45](../../.tasks/blocked/s9cqey45.md),
  saved in jj change `vytpwlxu` (`42eed4b8`).
- [Earlier SCIM management follow-up, YATL 1c682zm5](../../.tasks/open/1c682zm5.md).
  Its requirement to preserve historical bindings is superseded as a design
  requirement by this ADR; current behavior remains until deliberately changed.
- [Current Writ specification](../../writ/SPEC.md) and
  [fact-service documentation](../fact-services.md).
