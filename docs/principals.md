# Destination-bound SSH principals

This document specifies Epithet's interoperable SSH certificate principal
encoding. It is an issuance and target-validation protocol, not part of the
Writ policy language. Inventory resolves a requested host to an authorization
resource and principal domain; Writ authorizes the human-readable `(identity,
account, resource)` tuple, and the issuer encodes the allowed account and
domain after that decision.

## `epithet-principal-v1`

Let `SSHString(x)` be the RFC 4251 string representation of `x`: a four-octet
unsigned big-endian byte length followed by exactly that many bytes.

For a canonical principal domain and a byte-exact target account name:

```text
scheme   = "epithet-principal-v1"
preimage = SSHString(scheme)
         || SSHString(domain)
         || SSHString(accountName)
digest   = SHA-256(preimage)
principal = scheme || "-" || base64url-no-padding(digest)
```

`domain` is either a declared human-readable name such as
`ai-worker-pool-1` or a generated per-host value beginning
`epithet-host-id-v1:`. It is hashed byte-for-byte, as is the account name;
neither is normalized or case-folded. The complete 32-byte digest is encoded,
making the final principal exactly 64 ASCII bytes.

The scheme name is deliberately both the hash domain separator and the
visible prefix. A future incompatible encoding must use a new name in both
places.

## Normative test vector

This is an example input with an authoritative expected result. Independent
implementations can use it to verify byte-for-byte interoperability.

```text
domain:
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

The principal and generated domain values are opaque but not secret. Their
authorization strength comes from the CA signature, correct inventory
resolution of a requested hostname to a domain, and SHA-256 collision
resistance. Possession of a domain value does not authenticate a host.

All hosts configured with the same domain deliberately form one SSH
authorization boundary and derive the same principal for a given account.
Named domains make that boundary readable for fleets. Ordinary enrollment
generates a collision-resistant domain in the reserved
`epithet-host-id-v1:` namespace, giving one host its own boundary by default.

The literal domain is the durable security identity. Renaming a named domain
creates a different boundary; restoring the same name restores the same
boundary. Routine SSH host-key rotation does not change the domain or derived
principal. Deleting and recreating the same account name in the same domain
also preserves its principal; any previously issued certificate remains
bounded by its validity period.
