---
yatl_version: 1
title: Recover server startup after transient OIDC discovery failures
id: sqbfvvd7
created: 2026-10-11T09:55:23.640159Z
updated: 2026-10-11T10:42:19.255523Z
author: Brian McCallister
priority: high
---

Recover service startup after transient OIDC discovery failures. CA and control validate local configuration and bind listeners before discovery, then retry transient failures indefinitely with 1s exponential backoff capped at 30s and half-to-full jitter. Shutdown cancels discovery; permanent configuration, trust, and metadata failures remain fatal. GET /readyz reports completed startup for both services, while existing bootstrap endpoints remain available and pending authentication fails closed. Keep the existing CA construction interface, synchronous discovery for ordinary callers, and original signing-key fetching and verification behavior. Validate automatic recovery and certificate issuance without restarting after an outage longer than the supervisor socket deadline, plus cancellation, permanent failures, retry bounds, and concurrency.

---
# Log: 2026-10-11T09:55:23Z Brian McCallister

Created task.

---
# Log: 2026-10-11T09:58:17Z Brian McCallister

Started working.

---
# Log: 2026-10-11T10:24:43Z Brian McCallister

Implemented service-owned OIDC discovery recovery with early listeners, typed transient failure classification, capped jittered backoff, cancellation, explicit retry/recovery logs, standalone and combined liveness/readiness, and dependency errors for unavailable signing keys. Kept interactive discovery bounded and permanent discovery/configuration/trust errors fatal. Changed CA fact configuration to accept the caller-owned validator, removing hidden external discovery from CA construction. Verified make -B build, full make test, and race checks for pkg/oidc, cmd/epithet, pkg/ca, pkg/facts/control, and pkg/broker. Combined-server regression holds discovery down for eleven seconds, verifies live/unready and bootstrap responses, restores the same provider, checks actual certificate issuance without a restart, and checks shutdown during discovery. Fake-time coverage verifies continued retries and delay bounds over an hour-long outage.

---
# Log: 2026-10-11T10:24:43Z Brian McCallister

Closed.

---
# Log: 2026-10-11T10:37:38Z Brian McCallister

Reopened.

---
# Log: 2026-10-11T10:37:38Z Brian McCallister

Started working.

---
# Log: 2026-10-11T10:42:19Z Brian McCallister

Narrowed the implementation to startup discovery recovery. Removed /livez and the signing-key failure classification/verification changes; restored the original CA WithFacts interface and all affected caller fixtures. OIDC preparation now shares startup discovery internally through the existing validator configuration. Retained /readyz for completed CA/control discovery, pending-authentication dependency responses, retry/recovery logs, cancellation, and the recovery regression. Documentation lives in pkg/oidc and service lifecycle comments. Validation passed: make -B build, make test (including automatic recovery and certificate issuance after an eleven-second discovery outage), and go test -race for pkg/oidc, cmd/epithet, pkg/ca, pkg/facts/control, and pkg/broker.

---
# Log: 2026-10-11T10:42:19Z Brian McCallister

Closed.
