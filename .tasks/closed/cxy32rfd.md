---
yatl_version: 1
title: Run Epithet match after OpenSSH hostname canonicalization
id: cxy32rfd
created: 2026-09-03T21:40:43.320429Z
updated: 2026-09-03T21:53:15.116090Z
author: Brian McCallister
priority: high
tags:
- ssh
- canonicalization
- bug
---

OpenSSH evaluates ordinary `Match exec` predicates during its initial config
pass, before hostname canonicalization, and then evaluates the config again
with the effective host. Epithet must request a certificate only once, using
the final `%h` and the corresponding `%C`, while retaining tag gating and the
existing non-canonicalizing behavior.

Acceptance: the generated config uses the final pass; a live OpenSSH regression
proves tags selected from either the original or canonical hostname work,
`epithet match` runs exactly once with the canonical host, and `IdentityAgent`
uses the same final connection hash; tagged and untagged end-to-end behavior
continues to work.

---
# Log: 2026-09-03T21:40:43Z Brian McCallister

Created task.

---
# Log: 2026-09-03T21:40:49Z Brian McCallister

Started working.

---
# Log: 2026-09-03T21:53:11Z Brian McCallister

Changed generated SSH config to select IdentityAgent in a plain tagged block and invoke epithet match only in a final tagged block. Added live OpenSSH coverage for original-name tags, canonical-name tags, disabled canonicalization, one invocation, canonical %h, and matching final %C. Full test suite passes.

---
# Log: 2026-09-03T21:53:15Z Brian McCallister

Closed.
