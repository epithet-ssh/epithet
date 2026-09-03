# Destination-bound SSH principals

This document specifies Epithet's interoperable SSH certificate principal
encoding. It is an issuance and target-validation protocol, not part of the
Writ policy language. Writ authorizes a human-readable `(identity, account,
host)` tuple; the issuer encodes the allowed account and host after that
decision.

## `epithet-principal-v1`

Let `SSHString(x)` be the RFC 4251 string representation of `x`: a four-octet
unsigned big-endian byte length followed by exactly that many bytes.

For a canonical Epithet host ID and a byte-exact target account name:

```text
scheme   = "epithet-principal-v1"
preimage = SSHString(scheme)
         || SSHString(hostID)
         || SSHString(accountName)
digest   = SHA-256(preimage)
principal = scheme || "-" || base64url-no-padding(digest)
```

`hostID` is the complete canonical ASCII token
`epithet-host-v1-<base64url-no-padding>`. It is hashed byte-for-byte, as is the
account name; neither is normalized or case-folded. The complete 32-byte
digest is encoded, making the final principal exactly 64 ASCII bytes.

The scheme name is deliberately both the hash domain separator and the
visible prefix. A future incompatible encoding must use a new name in both
places.

## Normative test vector

This is an example input with an authoritative expected result. Independent
implementations can use it to verify byte-for-byte interoperability.

```text
host ID:
epithet-host-v1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8

account:
ubuntu

preimage (hex):
00000014657069746865742d7072696e636970616c2d76310000003b657069746865742d686f73742d76312d41414543417751464267634943516f4c4441304f4478415245684d554652595847426b6147787764486838000000067562756e7475

principal:
epithet-principal-v1-1G2FFzyyJShb63-XQoyRcIgz0rVX62Ob9KhnKc5k90o
```

The public Go implementation is `pkg/principal.DeriveV1`. The policy server
and `epithet host authorized-principals` both use it.

## Security and identity semantics

The principal and host ID are opaque but not secret. Their authorization
strength comes from the CA signature, correct binding of the requested
hostname to the host ID, and SHA-256 collision resistance. Possession of a
host ID does not authenticate a host.

Two hostnames intentionally assigned the same host ID are aliases and derive
the same principal. Independent hosts must not share an ID. The ID is immutable:
a machine that needs a different ID enrolls as a new host rather than rotating
the existing identity. Routine SSH host-key rotation does not change the host
ID or derived principal. Deleting and recreating the same account name on the
same host also preserves its principal; any previously issued certificate
remains bounded by its validity period.
