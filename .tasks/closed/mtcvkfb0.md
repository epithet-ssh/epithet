---
yatl_version: 1
title: Add agent kill command to force fresh certificate issuance
id: mtcvkfb0
created: 2026-09-04T21:47:05.591121Z
updated: 2026-09-04T21:55:02.905573Z
author: Brian McCallister
priority: medium
tags:
- agent
- broker
- testing
- certificates
---

Add `epithet agent kill AGENT_ID` as a testing and operational quality-of-life
command. The identifier is the connection hash shown by `epithet agent
inspect`.

Killing an agent evicts the corresponding entry from the running broker,
closes its per-connection SSH-agent socket, and discards its in-memory private
key and certificate. The next match for the same connection must generate a
new keypair and request a fresh certificate from the CA. Existing established
SSH sessions are not revoked or disconnected.

There is no cross-agent certificate reuse: every distinct connection hash gets
its own keypair and certificate. The broker map retains only routing and expiry
metadata; the agent is the sole credential owner. Repeated matches reuse a
certificate only by returning to that same agent until it expires or is killed.

Requirements:

- Extend the broker's newline-framed protocol with typed kill request and
  response messages rather than overloading match results.
- Resolve the broker using the same profile/socket rules as `agent inspect`.
- Reject an empty or unknown agent ID with a clear error; do not silently
  succeed on a typo.
- Remove the map entry atomically with respect to match and cleanup operations,
  then close the agent without leaving a reusable credential or socket.
- Preserve per-connection isolation: killing one agent cannot disturb another.
- Document that this is local credential eviction, not certificate revocation,
  and that already-established SSH sessions continue.

Acceptance:

- Broker and protocol tests prove that a known agent is removed and an unknown
  ID fails without changing broker state.
- A subsequent match for the killed connection obtains a new certificate,
  while another connection continues using its existing certificate.
- CLI tests cover request encoding, response handling, and useful user output.

---
# Log: 2026-09-04T21:47:05Z Brian McCallister

Created task.

---
# Log: 2026-09-04T21:55:02Z Brian McCallister

Implemented agent eviction end to end: typed broker kill protocol, profile-aware CLI command, fresh-certificate issuance on the next match, unknown-ID errors, per-agent isolation, and documentation. Removed the broker's duplicate raw-certificate field so the agent is the sole credential owner; closing an agent atomically clears its credential. Full tests, agent/broker race tests, and CLI build pass.

---
# Log: 2026-09-04T21:55:02Z Brian McCallister

Closed.
