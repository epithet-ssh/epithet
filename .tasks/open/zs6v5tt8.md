---
yatl_version: 1
title: Bind issued SSH certificate principals to registered host accounts
id: zs6v5tt8
created: 2026-08-23T14:53:16.777722Z
updated: 2026-08-23T18:59:56.903062Z
author: Brian McCallister
priority: critical
tags:
- writ
- security
---

Implement destination-bound SSH certificate issuance using a deterministic principal derived from the registered host identity key and requested account name.

Principal derivation:
- Define a versioned, domain-separated canonical derivation equivalent to:
  principal = "epithet-v1-" || base64url(SHA-256("epithet-account-principal-v1\0" || keyLength || canonicalHostKeyBlob || accountLength || accountName))
- Use fixed-width, specified-endian length fields; the canonical SSH public-key blob is ssh.PublicKey.Marshal(), never authorized_keys or known_hosts text. Account names are byte-exact.
- Publish normative test vectors and keep the complete digest. The principal is opaque but not secret; security comes from the CA signature, registered host-key identity, and hash collision resistance.
- A host alias bound to the same identity key derives the same principal. Different host identity keys must derive different principals for the same account.

Enforcement:
- The managed policy server resolves the requested hostname to an enrolled host identity key, authorizes the human-readable account@host tuple, derives the principal, and returns exactly that principal for certificate signing.
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
- A certificate issued for account@host A is rejected by host B even when both use the same account name and trust the same CA.
- The server and AuthorizedPrincipalsCommand match published derivation test vectors across supported key types and account-name edge cases.
- Textual differences in public-key files, comments, or whitespace do not affect derivation.
- Host aliases for one enrolled key derive the same principal.
- A cloned host key cannot silently create a second host identity.
- Planned and emergency host-key rotation follow the specified overlap and revocation behavior.
- Epithet Simple continues to issue account-name principals scoped to a CA trust domain; Epithet Enterprise uses deterministic destination-bound principals.

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
