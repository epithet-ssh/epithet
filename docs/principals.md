# Destination-bound SSH principals

This document specifies Epithet's interoperable SSH certificate principal
encoding. It is an issuance and target-validation protocol, not part of the
Writ policy language. Inventory resolves a requested host to an authorization
resource and principal realm; Writ authorizes the human-readable `(identity,
account, resource)` tuple, and the issuer encodes the allowed account and
realm after that decision.

## `epithet-principal-v1`

Let `SSHString(x)` be the RFC 4251 string representation of `x`: a four-octet
unsigned big-endian byte length followed by exactly that many bytes.

For a canonical principal realm and a byte-exact target account name:

```text
scheme   = "epithet-principal-v1"
preimage = SSHString(scheme)
         || SSHString(realm)
         || SSHString(accountName)
digest   = SHA-256(preimage)
principal = scheme || "-" || base64url-no-padding(digest)
```

`realm` is either a human-readable name such as
`ai-worker-pool-1` or a generated per-host value beginning
`epithet-host-id-v1:`. It is hashed byte-for-byte, as is the account name;
neither is normalized or case-folded. The complete 32-byte digest is encoded,
making the final principal exactly 64 ASCII bytes.

Named realms contain 1–253 ASCII letters or digits, with `.`, `_`, and `-`
allowed internally. They may use uppercase; `Fleet` and `fleet` are distinct
authorization boundaries. Managed records carry the realm as an attribute,
without a separate declaration or registry.

The scheme name is deliberately both the hash domain separator and the
visible prefix. A future incompatible encoding must use a new name in both
places.

## Normative test vector

This is an example input with an authoritative expected result. Independent
implementations can use it to verify byte-for-byte interoperability.

```text
realm:
ai-worker-pool-1

account:
ubuntu

preimage (hex):
00000014657069746865742d7072696e636970616c2d76310000001061692d776f726b65722d706f6f6c2d31000000067562756e7475

principal:
epithet-principal-v1-MTgFaDsSaL2IM0v4UljbMjiyxMUQiOK9KymVavQ2Y14
```

The public Go implementation is `pkg/principal.DeriveV1`. The policy server
and `epithet host authorized-principals` both use it.

## Security and identity semantics

The principal and generated realm values are opaque but not secret. Their
authorization strength comes from the CA signature, correct inventory
resolution of a requested hostname to a realm, and SHA-256 collision
resistance. Possession of a realm value does not authenticate a host.

All hosts configured with the same realm deliberately form one SSH
authorization boundary and derive the same principal for a given account.
Named realms make that boundary readable for fleets. Ordinary enrollment
generates a collision-resistant realm in the reserved
`epithet-host-id-v1:` namespace, giving one host its own boundary by default.

The literal realm is the durable security identity. Renaming a named realm
creates a different boundary; restoring the same name restores the same
boundary. Routine SSH host-key rotation does not change the realm or derived
principal. Deleting and recreating the same account name in the same realm
also preserves its principal; any previously issued certificate remains
bounded by its validity period.

Host commands use `--principal-realm` and `--principal-realm-file`. The local
identity file retains its existing path (the native state directory's `domain`
file by default), and generated realm values retain the `epithet-host-id-v1:`
prefix. Regenerate previously installed Epithet SSHD fragments to use
`--principal-realm-file` in `AuthorizedPrincipalsCommand`; the realm value itself
does not change.
