# Service topology and administrator authorization

Status: agreed design direction, with open contracts below. Implementation remains
paused. Consolidated September 23, 2026, from the September 20–21 discussion in
[Improve collaborative design process](codex://threads/01a0bca9-ccb1-7ec3-8b17-39c9c2cab632).

This replaces the September 19 options paper. It records decisions already made;
items explicitly marked as recommendations remain proposals.
The working change is `kvpltsws`, bookmark `codex/service-topology`, based on
`6f5e52e9`. Tracking task: `8rywbj6z` (separate directory and host administration).
CA-to-facts decisions below include the discussion through September 27, 2026.

## Agreed responsibilities

| Component | Owns | Authority toward fact services |
|---|---|---|
| CA | Issuance authentication, fact gathering, Writ evaluation, certificate signing | Read directory and inventory facts |
| `epithet-control` | Public administration, SCIM provisioning and host enrollment entry points; administrator authentication and role checks | Read facts and invoke administrative operations |
| Directory | User and group facts, directory mutation rules, concurrency checks, persistence and audit | Enforces the directory contract |
| Inventory | Host facts, inventory mutation rules, concurrency checks, persistence and audit | Enforces the inventory contract |

Control owns who may administer facts. The fact services own what constitutes a
valid change. Control calls their APIs; it does not open their storage directly.
Inventory does not acquire directory configuration or interpret user groups.

CA combines the issuance responsibilities in one process. Directory and inventory
remain independently replaceable fact providers. A custom LDAP directory or cloud
inventory adapter implements its small read contract; it need not implement
Epithet's built-in administration, SCIM, enrollment, or audit APIs. Control needs
read access to a custom directory to authorize administration of built-in inventory.

The earlier restriction that only CA may call fact services is superseded:
**CA reads for issuance; control reads and administers.**

## CA-to-facts API decisions

This contract is specifically CA -> directory/inventory. Control -> fact services
is a separate API design; its inspection and mutation requirements do not enlarge
the third-party issuance lookup contract.

Directory lookup uses the opaque authenticated `id`, with no required prefix or
provider-side OIDC claim mapping. It returns HTTP 200 with a user object for an
active user and HTTP 404 for an unknown or inactive user. There is no `active`
field or nullable success response. Caller authorization failures and provider
failures remain errors distinct from a missing user.

**Revision is optional logging metadata in both fact responses.** A provider may
return `revision` as an opaque string of at most 256 UTF-8 bytes. The CA logs it
as structured metadata alongside the lookup. Epithet does not interpret, compare,
order, or use it for caching or authorization. Omission is normal; Epithet does
not generate a substitute. A non-string or oversized value makes the provider
response invalid.

Providers need no global counter or snapshot-version semantics. During
implementation, remove mandatory source-revision requirements while retaining
the optional value for logging. This supersedes the earlier proposal to remove
revision metadata entirely.

This does not remove control-plane record revisions or the existing transactional
directory-rebinding check. Those protect mutations against concurrent changes
and belong to the separate administration contract.

The complete host response and optional user-field defaults still need to be
settled. The previously proposed `userName` fallback to `id`, empty default groups,
and optional user attributes are not promoted to agreed behavior by this decision.

## Deployment and discovery

`epithet-control` is always a separate service process. The combined `epithet server`
launcher starts CA, control, directory and inventory, with the public router.
Separately managed deployments run control explicitly as well. There is one
control implementation and one process boundary in both arrangements.

The combined launcher is a convenience for small, simple deployments. Its shared
lifecycle is an intentional deployment choice; this design does not require
changing it into an independently restarting supervisor. Operators who need
independent service lifecycles supervise the services separately.

Clients configure the CA address and discover control through a CA `Link` header.
In a combined deployment, the public router sends administration, SCIM and
enrollment traffic to control, and issuance traffic to CA. Control can share the
public origin with CA without administration passing through the CA process.
Separate deployments advertise the independently deployed control URL. Directory
and inventory service APIs remain private.

```mermaid
flowchart LR
    Client -->|issuance and discovery| CA[CA: authenticate, evaluate, sign]
    CA -->|read user facts| Directory
    CA -->|read host facts| Inventory
    Client -->|administration at discovered URL| Control[epithet-control]
    Provisioner[SCIM provisioner] --> Control
    Host[Enrolling host] --> Control
    Control -->|read facts and directory operations| Directory
    Control -->|inventory operations| Inventory
```

The diagram shows logical destinations; the combined public router is omitted.
CA discovery supplies the control URL to Epithet clients. This does not imply
that a SCIM provider implements Epithet discovery.

Process separation keeps administration execution outside CA's process. It does
not eliminate shared-host resource contention or fact-store contention. Initial
client discovery still depends on CA; no independent recovery/bootstrap workflow
has been agreed.

## Human administration

Control validates the administrator's OIDC credential, maps the identity using
the same identity semantics as issuance, and obtains the actor's directory facts.
An active directory user is required, including for explicit user-ID grants.

There are two independently assignable roles, configured in control:

- Directory administrator, granted through configured user IDs or directory groups.
- Inventory administrator, granted through configured user IDs or directory groups.

The same user or group may hold both. Fact services do not repeat these role
checks or maintain their own administrative group configuration. They authenticate
control's authority, enforce operation invariants, and record the actor in audit.

For a human mutation, the flow is:

1. Client discovers control and sends its authenticated request there.
2. Control validates identity, looks up current directory facts and checks the
   role for the requested administrative domain.
3. Control signs the backend request, including the authenticated actor.
4. The backend verifies the request and the signer's authority, validates the
   mutation and relevant revisions, and persists it with its audit record.

Directory alias rebinding must retain its existing transactional check of the
directory revision used for authorization. Control must carry that revision in
authenticated request data. Inventory currently has a lookup-to-write race with
directory changes; this split must not claim a cross-service atomic authorization
snapshot. The freshness contract is identified below for explicit agreement.

## Service trust and signed requests

Control has its own persistent signing key pair. Its private key is configured;
fact services receive its public key out of band. They do not receive control's
private key or the SSH CA private key. Automatic key provisioning was not selected.

| Caller credential | Permitted use |
|---|---|
| CA signing key | Fact reads for issuance; no administrative authority |
| Control signing key | Fact reads and authorized backend administration |
| Human OIDC credential | Authentication to control, followed by directory-backed role checks |
| SCIM provisioning credential | SCIM provisioning only; no human administrator role |
| Enrollment credential or pending-enrollment flow | Existing enrollment semantics; no human administrator role |

SCIM keeps its existing operator-supplied random bearer token. The topology
refactor does not replace that external credential with OIDC or a client JWT.

A recognized signature alone does not grant every permission. The backend must
distinguish the trusted CA reader from the trusted control administrator.

For human administration, control mints a short-lived JWT with the authenticated
actor as `sub`. The signature also covers the destination service, HTTP method,
request target and body hash, extending the existing request-bound service JWTs.
The receiving fact service records the actor. The operation is already identified
by the HTTP request, including its body; no separate operation claim is needed.

The signing identity and the actor are different: control is the trusted signer;
`sub` identifies the human whose request control authorized. Client-supplied actor
metadata cannot replace control's authenticated attribution.

The existing implementation uses a 60-second token lifetime and binds host/path,
method and body. It has no actor claim and no single-use replay enforcement.
These are source observations, not evidence that the new contract is implemented.
The agreed refactor preserves existing freshness and replay semantics.

## Contract decisions and remaining discussion

### 1. Where do provisioning and enrollment credentials get checked?

We agreed that both flows enter through control and retain their existing kinds
of authorization, including the existing random SCIM bearer token. We have not
specified the complete private request contract,
including audit attribution when there is no authenticated human.

The code currently validates the static SCIM bearer token in the SCIM HTTP
adapter. Inventory validates and consumes an enrollment token together with the
host transition under its storage lock. SCIM audit uses `scim`; enrollment audit
uses `host`. Neither label is an authenticated human identity.

**Agreed:** control validates the existing random SCIM bearer token and signs
its downstream request to directory.

**Remaining recommendation:** inventory continues to own atomic
enrollment-token validation/consumption and the pending-versus-active transition;
control admits and signs that enrollment request. Preserve the current audit
meaning without representing an anonymous host as an authenticated user.

Forwarding the SCIM bearer token for backend validation was not selected: control
owns that check. Moving enrollment-token state into control would split token
consumption from the host write, adding coordination and state ownership we have
not agreed to introduce.

Confirm enrollment validation ownership and specify how machine or anonymous
provenance is distinguished from a human `sub` in the private wire format.
No new credential store or actor namespace is selected here.

### 2. Freshness and replay: preserve existing semantics (agreed)

Look up the human actor's directory facts for
each administrative request, mint a token for that request, retain the current
short lifetime, and preserve the directory-rebinding revision check. Explicitly
accept the existing inventory lookup-to-write race. This avoids introducing a
cross-service transaction or revocation protocol.

No freshness or replay behavior changes are included in this refactor. Keep the
60-second service-token lifetime and existing operation/revision checks. Request
binding prevents reuse for a different bound request; it does not make the same
request single-use. No replay store or new revocation mechanism is proposed.
The required extensions are control's distinct authority and authenticated actor
attribution, already agreed above.

The current target binding excludes the query string. If private operations use
query parameters that change the operation, those parameters must be covered by
the signed request contract. Exact encoding is an implementation detail once the
contract is settled; silently treating host/path as the entire request is not.

### 3. Enumeration: refactor first, optimize second (agreed)

The earlier options analysis found that directory enumeration reads all user
facts through one SQLite connection and inventory enumeration clones and sorts
all records under its read lock. Control's separate process does not solve those
backend costs. No load-test result is claimed.

Preserve current listing behavior in this refactor. Pagination and enumeration
optimization come afterward; they are not prerequisites for the service split.
This refactor makes no new backend load-isolation performance promise.

Existing task `mxqw1xmw` covers directory users/groups storage pagination. It does
not yet cover the full administrative `ListUserFacts` projection or inventory
listing. Scope those additions when taking up optimization; this refactor does
not expand that task or add it as a dependency.

## Routine implementation choices and scope boundaries

After the contracts above are settled and implementation is requested, exact CLI
and configuration names, Link relation naming, package organization, and endpoint
encoding can be proposed together as the concrete interfaces for this design.
They do not require reopening the selected topology. Server configuration remains
separate from management-client agent profiles and sockets.

This agreement does not add CA proxy modes, in-process control, mTLS, automatic
key generation, independent outage bootstrap, new OIDC token kinds or application
registrations, workload credentials, or compatibility shims. Any need for those
would be a separate behavior discussion. Richer group-management UX remains in
`1c682zm5`.

## Why this topology was selected

The September 19 exploration compared materially different ownership models:

| Option | Benefit | Cost or reason it was not selected |
|---|---|---|
| A: inventory consults directory | Fewer services; narrow one-way dependency | Inventory owns user authorization and directory configuration |
| B: administration inside CA | Fewer processes and signing identities | Administrative execution and payloads share the issuing process |
| C: separate control service (selected) | Central role checks; focused fact providers; separate administration process | Another privileged service, signing key and private management contract |
| D: combined directory/inventory provider | Simpler all-built-in deployment | Built-in inventory with a custom directory still needs an authorization solution |
| E: IdP claims or explicit grants without directory | No directory authorization lookup | Changes directory-backed deactivation and group semantics |
| F: client carries an authorization assertion | Management payloads bypass the authorizer | Adds a client exchange and delegated-authority protocol not requested |
| G: backend asks CA to authorize | Large management responses bypass CA | Reverse backend-to-CA dependency and administration authority in CA |

The selected control JWT is a service-to-service request credential. It does not
introduce option F's client-carried delegation flow. The public router and CA's
Link preserve the simple client configuration without either hosting control in
CA or adding an optional CA proxy mode.

## Validation for the eventual implementation

- Exercise issuance and administration through both the combined launcher and
  independently deployed services, keeping control separate in both.
- Test all-built-in and mixed custom-directory/built-in-inventory and
  built-in-directory/custom-inventory deployments using minimal read adapters.
- Verify active-user requirements, explicit ID and group grants, role separation,
  deactivation and group removal, and directory-rebinding revision conflicts.
- Reject CA-reader credentials at administrative endpoints, untrusted actor
  attribution, and requests with incorrect destination, method, target or body.
  Exercise expiry and the replay behavior selected above.
- Exercise SCIM provisioning and enrollment through control, including invalid
  credentials, token consumption, pending admission and backend-owned audits.
- Verify discovery and routing, plus the existing combined shared lifecycle and
  separately supervised process behavior. Do not claim fresh-client recovery
  during a CA outage or backend load isolation without a separate agreed contract.
- Run `make build` and `make test`; run `go test -race ./pkg/broker` if broker
  concurrency paths change. This document does not claim those future behaviors
  have been implemented or tested.

## Source references

These references anchor the existing behavior described above:

- [Current authorization and management dispatch](../pkg/inventoryserver/control.go)
- [Service JWT signing and verification](../pkg/serviceauth/serviceauth.go)
- [SCIM credential validation and adapter](../pkg/directory/scim/http.go)
- [Directory storage, revisions and audit](../pkg/directory/sqlitestore/store.go)
- [Enrollment, host storage and audit](../pkg/inventory/managed.go)
- [Combined launcher](../cmd/epithet/server.go) and [public router](../cmd/epithet/router.go)
- [Client discovery](../pkg/caclient/inventory.go)
