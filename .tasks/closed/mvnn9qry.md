---
yatl_version: 1
title: Implement host enrollment and destination trust
id: mvnn9qry
created: 2026-08-23T17:27:15.170420Z
updated: 2026-09-03T03:26:32.897980Z
author: Brian McCallister
priority: critical
tags:
- epithet-enterprise
- host-enrollment
- security
- ssh
---

Implement Epithet Enterprise host enrollment, sshd integration, client destination trust, and administrative control-plane authentication. Do not require a persistent host agent.

Host identity and enrollment:
- Treat a designated sshd host public key, preferably Ed25519, as the host identity. Derive the host ID from the SHA-256 fingerprint of the canonical SSH public-key encoding while storing the complete public key needed for known_hosts records and deterministic account-principal derivation.
- Require proof of possession by signing a policy-server nonce with the corresponding host private key.
- Keep admission separate from identity: a scoped enrollment token, trusted machine identity, or administrator approval authorizes initial enrollment and the hostnames the key may claim.
- Detect duplicate or cloned host keys. Keep security-sensitive labels server or administrator assigned.
- Specify routine rotation authenticated by the old key and administrative recovery after compromise.

CA-only bootstrap and communication:
- Keep the CA URL as the only service location configured on hosts and user endpoints.
- Extend typed Link discovery from the CA to advertise a host-control descriptor. The CA is a bootstrap locator only; enrollment, registration, administration, and host-key lookup traffic go directly to the managed policy/control service.
- Cache discovered endpoints so normal operations do not depend on repeated CA discovery.
- Make Epithet Simple advertise no Enterprise host-control capability.

One-shot host installation:
- Provide an explicit privileged command such as epithet hosts enroll --ca-url URL with optional --token, --host-key, and --hostname overrides.
- Default to the designated sshd Ed25519 host key and system hostname. An overridden hostname is a proposal until approval or token scope authorizes it.
- Enroll the host key, install the Epithet SSH CA public key, install an sshd drop-in and offline AuthorizedPrincipalsCommand, validate with sshd -t, roll back on failure, and reload sshd.
- Write active enrollment state atomically only after approval and successful local installation. Missing state is a safe unenrolled condition; corrupt state or a host-key mismatch is a hard error.
- Do not install or require a persistent host agent. An idempotent host sync command may later provide advisory inventory, health, or configuration refresh; packaging-specific schedulers must not be part of the authorization invariant.

Deterministic sshd authorization:
- Install a root-owned AuthorizedPrincipalsCommand invoked with the target username and run as a dedicated unprivileged account.
- Derive the expected principal locally from the designated canonical host public-key blob and target username using the versioned algorithm specified by zs6v5tt8.
- Emit AuthorizedPrincipalsFile-format output without reading per-account UUID mappings and without contacting the policy server.
- Support old/new identity-key overlap during planned rotation.

Client host verification:
- Publish enrolled host public keys through the authenticated control plane in known_hosts format.
- Integrate a local cached lookup with OpenSSH KnownHostsCommand and StrictHostKeyChecking=yes. Avoid repeated network calls because OpenSSH may invoke the command multiple times per connection.
- Bind hostname aliases to enrolled host-key identities and fail closed on missing, conflicting, stale, or mismatched keys.
- Leave a documented path to SSH host certificates without requiring a host CA in the first implementation.

Administrative authentication:
- Run approval and enrollment-window commands from an administrator endpoint using the existing user-side Epithet agent and its OIDC session.
- Extend the user agent broker protocol with a token operation supporting normal acquisition and one forced refresh. Return only the short-lived OIDC ID token over the user-owned broker socket; never expose the refresh token.
- Have the admin CLI discover the control endpoint from its configured CA profile, obtain an ID token from the local agent, call the control API directly, and retry once with forced refresh after a 401.
- Authorize enrollment approver, host administrator, policy administrator, and audit reader roles in a control-plane RBAC layer separate from Writ SSH-access rules. Audit the validated human identity for every administrative mutation.

Enrollment admission approach:
- Keep Enterprise enrollment closed by default. Possession of a newly generated host key proves control of that key but does not authorize the machine to join.
- Support three admission modes through one state machine: a manual enrollment window, a scoped enrollment token, and a pluggable external machine identity or attestation.
- Model transitions as Requested -> Pending -> Approved -> Active, with Denied and Expired terminal outcomes. Token or attestation admission uses the same transitions and records an automated approving actor.
- Require host-key proof of possession before accepting any request. The unapproved host key authenticates polling for its own request; approval promotes that key into the durable host authentication identity.
- At approval, the administrator or admission template assigns the canonical hostname and security-sensitive labels.

Manual enrollment steps:
1. An authenticated administrator uses the existing endpoint agent to open a narrow enrollment window with a short TTL, maximum request count, and optional hostname, source-network, or template constraints.
2. The host discovers the control plane from its CA URL and submits its public host key, signed proof of possession, proposed hostname, and minimal fixed-size metadata.
3. The server deduplicates by host-key fingerprint and returns an opaque request ID plus a human-verifiable fingerprint or short comparison code.
4. The administrator lists pending requests, verifies the expected fingerprint out of band when appropriate, and approves or denies the exact request.
5. The host polls using host-key authentication. Approval permits the installation flow to complete and activates the enrolled host record.
6. The enrollment window closes automatically at its TTL or request limit.

Pending-queue controls:
- Keep pending entries strictly size-bounded, short-lived, deduplicated by fingerprint, and preferably in memory. Do not append untrusted requests to durable event history until approval.
- Accept only small fixed-shape records before approval.
- Apply global and per-source rate limits, avoid attacker-amplified logging, and expose aggregate rejection metrics.
- Outside an explicit enrollment window, reject manual requests before allocating per-request state.
- Treat permanently open anonymous enrollment as an explicit development-only mode.

Token and automated enrollment:
- Tokens bypass human confirmation but not host-key proof of possession. Make them short-lived, scoped to hostname patterns and assigned labels, single-use by default, hashed at rest, and atomically bound to the first redeeming fingerprint.
- Invalid tokens fail outright and never silently fall back to pending enrollment.
- Record the token identifier or attestation authority as the approving actor.
- Add pluggable proofs for cloud instance identity, Kubernetes workload identity, TPM attestation, configuration-management credentials, or comparable deployment roots.
- Do not begin with broad reusable bearer tokens.

Acceptance:
- A valid scoped token approves the exact redeeming host key and cannot be replayed for a second key.
- Without a token, enrollment becomes pending only during an open window; otherwise it allocates no request state.
- Pending entries expire, deduplicate, and obey configured queue and rate limits.
- Approval binds the exact displayed host-key fingerprint; proposed names and labels do not become authoritative without approval or token scope.
- A newly enrolled ephemeral host becomes connectable without manually editing policy or known_hosts.
- A client refuses a server presenting a key different from the registered key.
- sshd derives principals and authenticates entirely from local state during control-plane unavailability.
- Installation is idempotent, sshd-validated, and rollback-safe across supported platforms.
- Document Epithet Simple as account-name principals scoped to a CA domain and Enterprise as deterministic host/account principals with verified host keys.

Related: zs6v5tt8 defines and implements deterministic destination-bound principal derivation.

---
# Log: 2026-08-23T17:27:15Z Brian McCallister

Created task.

---
# Log: 2026-08-23T18:31:03Z Brian McCallister

Recorded enrollment admission design: default-closed manual windows, bounded ephemeral pending queue, scoped token auto-approval, and pluggable machine attestation.

---
# Log: 2026-08-23T18:59:56Z Brian McCallister

Revised host design: one-shot enrollment plus offline deterministic AuthorizedPrincipalsCommand; no persistent host agent, per-account mapping state, or correctness-critical scheduler.

---
# Log: 2026-09-03T03:26:32Z Brian McCallister

Closed: Superseded by the managed-control-plane dependency chain 548x7rsk -> vpcj6szt -> v6hz0x82 -> 0rm7n86c -> 508fj5h3 -> b7pbqbss.
