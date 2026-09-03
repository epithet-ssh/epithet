---
yatl_version: 1
title: Bind issued SSH certificate principals to registered host accounts
id: zs6v5tt8
created: 2026-08-23T14:53:16.777722Z
updated: 2026-09-03T02:24:20.853141Z
author: Brian McCallister
priority: critical
tags:
- writ
- security
---

Implement destination-bound SSH certificate issuance using a deterministic principal derived from the host identity public key and requested account name, while retaining an explicit account-name compatibility mode for hosts and ephemeral host patterns that do not have individual identity keys.

Principal derivation:
- Use the single scheme identifier `epithet-principal-v1` as both the visible principal prefix and the hash domain separator.
- Define `SSHString(x) = uint32be(len(x)) || x`, where the length is the number of octets and is encoded as an unsigned four-byte big-endian integer.
- Define the v1 derivation exactly as:
  ```text
  scheme = "epithet-principal-v1"
  preimage = SSHString(scheme) || SSHString(ssh.PublicKey.Marshal()) || SSHString(accountName)
  digest = SHA-256(preimage)
  principal = scheme || "-" || base64url-no-padding(digest)
  ```
- The resulting principal is exactly 64 ASCII bytes: `epithet-principal-v1-` followed by the 43-character unpadded base64url encoding of the complete SHA-256 digest.
- The canonical SSH public-key blob is `ssh.PublicKey.Marshal()`, never authorized_keys or known_hosts text. Account names are byte-exact; string lengths count bytes, not characters.
- Publish normative test vectors and keep the complete digest. The principal is opaque but not secret; security comes from the CA signature, registered host-key identity, and hash collision resistance.
- A host alias bound to the same identity key derives the same principal. Different host identity keys must derive different principals for the same account.

Principal modes:
- Configure a deployment-level default mode with exactly two values: `account-name-principals` and `hashed-principals`.
- Allow an exact host or host-pattern inventory entry to override the default. Resolution remains exact host first, otherwise first matching pattern; the matched entry's override wins over the deployment default.
- In static inventory, an exact host whose effective mode is `hashed-principals` must provide its designated identity public key. Missing or invalid key material fails closed during inventory validation.
- A static pattern may override to `account-name-principals`, supporting ephemeral fleets whose instances are not individually enrolled. A static pattern cannot provide one shared key for `hashed-principals`; doing so would destroy destination isolation. Hashed principals for pattern-matched names require another inventory implementation that resolves the individual instance's identity key.
- An exact host may explicitly override to `account-name-principals` as a compatibility escape hatch.
- Account grounding remains independent of principal mode. For example, a pattern with `accounts: [ubuntu]` prevents issuance for other account names but does not destination-bind the resulting `ubuntu` certificate.
- The server-side effective mode and target-side sshd validation mode must agree. Account-name certificates are reusable across every host that trusts the CA and accepts literal account-name principals; hashed-mode hosts must accept only their locally derived principals.

Enforcement:
- In `account-name-principals` mode, the policy server continues to return the requested account name for certificate signing and discloses that it is not destination-bound.
- In `hashed-principals` mode, the policy server resolves the requested hostname to its identity public key, authorizes the human-readable account@host tuple, derives the principal, and returns exactly that principal for certificate signing.
- The target sshd uses an offline AuthorizedPrincipalsCommand that derives the same principal from its designated local host identity public key and the target username. It does not read a per-account mapping and never contacts the control plane during authentication.
- Reject registration of one designated identity key as multiple independent hosts; cloned keys destroy destination isolation and are a critical conflict.
- No per-account UUID registry, account inventory synchronization, mapping rotation API, host daemon, or correctness-critical scheduled job is required.
- Account existence remains enforced by sshd before AuthorizedPrincipalsCommand is invoked. A certificate for a nonexistent account is unusable; optional inventory reporting may support visibility or linting but is never authoritative for principal derivation.

Lifecycle:
- Specify a designated host identity key, preferably Ed25519, independently of additional sshd host keys offered for algorithm compatibility.
- Planned host-key rotation temporarily accepts derivations from old and new identity keys, issues only against the new key after activation, and removes the old derivation after the certificate validity window.
- Emergency rotation after compromise requires administrative recovery and may revoke old derivations immediately.
- Document that deleting and recreating the same account name preserves its derived principal on that host; exposure from a previously issued certificate is bounded by certificate TTL.

Acceptance:
- The deployment default and exact-host or pattern override deterministically select `account-name-principals` or `hashed-principals` for every resolved host.
- Static inventory rejects an exact hashed-principal host without a valid identity public key and rejects a shared identity key on a pattern entry.
- An account-name pattern supports an ephemeral fleet with a grounded default account such as `ubuntu` or `arch`, with the cross-host reuse boundary clearly documented.
- A certificate issued for account@host A is rejected by host B even when both use the same account name and trust the same CA.
- The server and AuthorizedPrincipalsCommand match published derivation test vectors across supported key types and account-name edge cases.
- Textual differences in public-key files, comments, or whitespace do not affect derivation.
- Host aliases for one enrolled key derive the same principal.
- A cloned host key cannot silently create a second host identity.
- Planned and emergency host-key rotation follow the specified overlap and revocation behavior.
- Epithet Simple continues to issue account-name principals scoped to a CA trust domain; Epithet Enterprise uses deterministic destination-bound principals.

Implementation sequence:
1. `docs: specify destination-bound principal design` records this protocol, mode semantics, and implementation plan.
2. `feat: derive destination-bound principals` adds public `pkg/principal` constants, v1 derivation, normative vectors, and unit tests without changing runtime behavior.
3. `feat: add the host authorized-principals command` adds the offline `epithet host authorized-principals` consumer, repeatable host keys for planned rotation, and an explicit temporary literal-account overlap option for migration.
4. `refactor: separate policy and issuance host data` lets inventory resolution carry issuance metadata without exposing it to pure Writ evaluation; behavior remains account-name-only.
5. `feat: issue configured host principals` atomically adds deployment `principal-mode`, exact/pattern overrides, static `identity-key`, validation, and hashed issuance.
6. `test: verify destination-bound SSH access` proves acceptance on the intended host, rejection on another hashed host, account-name pattern fallback, and fail-closed configuration behavior.
7. `docs: document principal modes and host installation` updates the guide, examples, Writ specification, and sshd setup after runtime behavior exists.

Public interfaces selected for the first implementation:
- Shared derivation package: `pkg/principal`, exporting `SchemeV1` and `DeriveV1`.
- Offline helper: `epithet host authorized-principals`.
- Configuration fields: `principal-mode` and `identity-key`; an omitted deployment mode preserves `account-name-principals` compatibility.

Until this task is complete, documentation and the Writ specification must describe the current implementation as account@CA-trust-domain with host selectors enforced only at issuance time.

---
# Log: 2026-08-23T14:53:16Z Brian McCallister

Created task.

---
# Log: 2026-08-23T14:56:14Z Brian McCallister

Documented the destination-binding invariant and current compatibility-profile limitation in writ/SPEC.md and docs/policy-server.md. No registration API or UUID issuance implementation exists yet; task remains open.

---
# Log: 2026-08-23T17:28:11Z Brian McCallister

Host-agent, sshd integration, host-key registration, and client verification implementation is tracked in mvnn9qry.

---
# Log: 2026-08-23T18:59:56Z Brian McCallister

Superseded per-account UUID registration with versioned deterministic principal derivation from the canonical registered host key and account name.

---
# Log: 2026-09-03T02:15:11Z Brian McCallister

Specified SSH-string-framed epithet-principal-v1 derivation and default/per-host-or-pattern principal modes, including static ephemeral-fleet fallback semantics.

---
# Log: 2026-09-03T02:24:20Z Brian McCallister

Added the ordered Jujutsu implementation stack and selected the public package, host command, and configuration names.
