# Destination-bound SSH principals

This document specifies Epithet's interoperable SSH certificate principal
encoding. It is an issuance and target-validation protocol, not part of the
Writ policy language. Writ authorizes a human-readable `(identity, account,
host)` tuple; the issuer encodes the allowed account and host after that
decision.

## `epithet-principal-v1`

Let `SSHString(x)` be the RFC 4251 string representation of `x`: a four-octet
unsigned big-endian byte length followed by exactly that many bytes.

For an SSH host public key and a byte-exact target account name:

```text
scheme   = "epithet-principal-v1"
preimage = SSHString(scheme)
         || SSHString(hostPublicKey.Marshal())
         || SSHString(accountName)
digest   = SHA-256(preimage)
principal = scheme || "-" || base64url-no-padding(digest)
```

`hostPublicKey.Marshal()` is the canonical SSH wire-format public-key blob.
Authorized-key whitespace and comments are not inputs. The account name is
not normalized or case-folded. The complete 32-byte digest is encoded, making
the final principal exactly 64 ASCII bytes.

The scheme name is deliberately both the hash domain separator and the
visible prefix. A future incompatible encoding must use a new name in both
places.

## Normative test vector

This is an example input with an authoritative expected result. Independent
implementations can use it to verify byte-for-byte interoperability.

```text
host public key:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75S vector-comment

account:
ubuntu

preimage (hex):
00000014657069746865742d7072696e636970616c2d7631000000330000000b7373682d6564323535313900000020fef78393255a2818d8fd2cee253f0a1b5fdcc8be2b1c72e35e4e904cb103be52000000067562756e7475

principal:
epithet-principal-v1-pV-Og_HWXFEBuK01mJV1xsd1VpSny25vP3SwcfikJmg
```

The public Go implementation is `pkg/principal.DeriveV1`. The policy server
and `epithet host authorized-principals` both use it.

## Security and identity semantics

The principal is opaque but not secret. Its authorization strength comes from
the CA signature, correct binding of the requested hostname to the designated
host public key, and SHA-256 collision resistance.

Two hostnames intentionally assigned the same key are aliases and derive the
same principal. Independent hosts must not share that key. Deleting and
recreating the same account name on the same host also preserves its
principal; any previously issued certificate remains bounded by its validity
period.
