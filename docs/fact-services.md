# Implementing a fact service

A directory or inventory provider only implements one read endpoint. It does not
validate user login tokens, evaluate Writ, or implement Epithet administration.
CA authenticates the user, looks up current facts, evaluates policy locally, and
signs the certificate. Control may also read directory facts to authorize admins.

| Service | Request | Successful response |
|---|---|---|
| Directory | `GET /lookup?id=OPAQUE_ID` | Active user object |
| Inventory | `GET /lookup?host=HOST_NAME` | Active host object |

Configure each service's root URL on CA. The client appends `/lookup`; a root may
include a path prefix. Use standard URL query encoding, exactly one named query
parameter, and no request body. Directory IDs are opaque. Host lookup names are
ASCII case-folded, with a trailing dot removed. Return `404` for unknown or inactive
records. Authentication errors and service failures must use their own non-200,
non-404 status; they must not masquerade as an absent record.

Send `Cache-Control: no-store` on every lookup response, including errors. CA
performs fresh reads for each issuance attempt, follows no redirects, and has no
application fact cache. A successful response must be a JSON object, not `null`.
The response limit is 64 KiB.

## Directory

The smallest response is:

```json
{"id":"opaque-user-id"}
```

A fuller response is:

```json
{
  "id": "opaque-user-id",
  "userName": "alice",
  "groups": ["operators"],
  "userType": "employee",
  "department": "engineering",
  "organization": "example",
  "revision": "provider-defined"
}
```

`id` is required and must match the requested ID. All other fields are optional.
Omitted groups mean no memberships; omitted attributes have no value. There is no
`active` field: returning the object asserts that this user is active. CA uses the
ID for policy identity. A missing username does not match a `userName` selector;
ID is used only as a display/certificate Key ID fallback.

## Inventory

```json
{
  "names": ["host.example", "host.internal"],
  "accounts": ["root", "deploy"],
  "labels": {"env":"production"},
  "principal": {"mode":"epithet-principal-v1", "domain":"fleet-id"},
  "revision": "provider-defined"
}
```

`names`, `accounts`, and `principal` are required. Names contain every equivalent
normalized host name, including the requested name. Writ evaluates the entire
list, including denies. Names must be nonempty and unique. Optional `labels`
default to no labels.

Accounts must be explicit: `null` imposes no inventory restriction, `[]` permits
no accounts, and an array of names restricts issuance to those accounts. Writ
still decides whether access is allowed.

Principal modes are `{"mode":"account-name"}` or
`{"mode":"epithet-principal-v1","domain":"..."}`. The latter requires a valid,
nonempty opaque principal domain. The domain is credential scope, not a hostname
or a policy selector. Do not substitute it into `names`. Multiple hosts can share
a domain intentionally; all then accept the same principal for a given account.

Both response types may include `revision`, an opaque string of at most 256 UTF-8
bytes. It is logged only: no comparison, ordering, caching, or authorization
semantics. Omission needs no replacement. Null, a non-string, or an oversized
revision invalidates the response. This metadata is unrelated to control-plane
mutation revisions.

## Request authentication

Trust the configured CA public key for reads. If control needs reads, configure
its distinct public key as well. Only control's key authorizes private mutation
APIs. These public keys are provisioned out of band; no shared user credential is
sent to a fact provider.

Each request has `Authorization: Bearer JWT`, signed with the calling service's
SSH private key. `pkg/serviceauth` is the reference implementation:

| Claim | Meaning |
|---|---|
| `iss` | OpenSSH SHA256 fingerprint of the signing key |
| `aud` | `epithet-directory` or `epithet-inventory` |
| `iat`, `exp` | Unix seconds; token lifetime is 60 seconds |
| `jti` | Random request identifier |
| `htm` | Exact HTTP method |
| `htu` | HTTP authority plus escaped path and raw query, e.g. `facts.example/lookup?id=a%2Bb` |
| `bh` | Unpadded base64url SHA256 digest of the body; empty-body digest for GET |

Verify signature, audience, expiry and issued-at freshness, method, target including query,
and body digest. Algorithms follow the SSH key type: Ed25519 uses EdDSA, RSA
uses PS256, and supported ECDSA curves use ES256/ES384. Preserve authority, escaped
path, and query through proxies. Rewriting any of them invalidates the signature.
Tokens are request-bound but do not use a replay database. TLS remains necessary
for remote services; Unix sockets are supported for local services.

See [inventory-api.yaml](inventory-api.yaml) and
[directory-api.yaml](directory-api.yaml) for response schemas, and
[inventory.md](inventory.md) for deployment configuration. Bespoke providers do not
need Epithet's private `/manage`, `/actor`, or `/scim` backend endpoints.
