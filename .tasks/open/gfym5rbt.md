---
yatl_version: 1
title: 'Post-refactor polish backlog (final-review triage, all OK-TO-DEFER): serviceauth NewVerifier comma-ok assert + RSA min-modulus; broker Token TOCTOU redundant fetch (generation counter); abandoned-flight wind-down bound; require-in-goroutine in broker tests; sshd tag-test tripwire join; agent.Serve single-shot guard; jti minted-not-tracked replay note; caserver oversized-body test; consider slog request-access log for CA/policy'
id: gfym5rbt
created: 2026-08-14T19:42:15.760653Z
updated: 2026-09-06T03:21:04.735831Z
author: Brian McCallister
priority: medium
---

---
# Log: 2026-08-14T19:42:15Z Brian McCallister

Created task.

---
# Log: 2026-09-06T03:21:04Z Brian McCallister

Review 2026-09-05 follow-up: validate CA certificate duration, validity interval, and nonempty principals; inspect broker connection-hash paths and pre-existing runtime-directory ownership. These are source-level hardening observations, not demonstrated remote exploits. govulncheck found no reachable vulnerabilities but x/crypto v0.55.0 has imported-package SSH advisories GO-2026-6354 and GO-2026-6355 fixed in v0.56.0; update and recheck. Details in docs/security-review-2026-09-05.md.
