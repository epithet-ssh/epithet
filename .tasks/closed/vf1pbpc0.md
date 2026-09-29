---
yatl_version: 1
title: Investigate and likely remove accept-account-name migration support
id: vf1pbpc0
created: 2026-09-28T21:14:13.479015Z
updated: 2026-09-29T02:15:32.371431Z
author: Brian McCallister
priority: high
---

The user has repeatedly specified that migration paths and backward compatibility are not requirements before 1.0. During the CLI audit, `host authorized-principals --accept-account-name` surfaced as a migration feature despite that direction. Investigate why it was introduced and retained; the expected outcome is removal unless a concrete current requirement unrelated to migration justifies it.

Current behavior:
- cmd/epithet/host.go declares the flag and adds the literal account name alongside the destination-bound derived principal.
- The help calls this a "bounded migration", but there is no enforced deadline or expiration.
- docs/policy-server.md describes the broader account-name acceptance across hosts trusting the CA while this is enabled.
- cmd/epithet/host_test.go covers migration output and literal-account validation; docs/cli-flag-audit.md catalogs the flag.

Work:
1. Trace the introduction and subsequent changes through repository history and relevant task/design records. Identify the original rationale and whether it had explicit user authorization; distinguish evidence from inference.
2. Determine whether any current use requires this flag beyond backward compatibility. Do not invent a migration requirement to preserve it.
3. Unless a concrete current requirement warrants discussing retention with the user, remove the flag, its literal-account output path, and code/tests/docs that exist solely to support it. Preserve normal destination-bound authorization.
4. Do not replace it with aliases, deprecation periods, migration modes, or another compatibility mechanism.
5. Report the origin and rationale found, update the CLI audit, and validate the change with make build and make test.

This task is deferred follow-up; the current request is to record the investigation and likely removal, not implement it during the CLI audit.

---
# Log: 2026-09-28T21:14:13Z Brian McCallister

Created task.

---
# Log: 2026-09-29T02:12:39Z Brian McCallister

Started working.

---
# Log: 2026-09-29T02:15:27Z Brian McCallister

Traced the option to ca25e503402e51a32b5c97a418d5c5e25fd86c2e (feat: add the host authorized-principals command), following the explicit temporary literal-account overlap item in zs6v5tt8 / design commit 4a91466. Subsequent host-key, host-ID, and principal-domain refactors retained it. Historical discussion did include trying the rollout without losing access to untouched hosts, but does not establish approval for this specific flag; the assistant later acknowledged that its proposed enrollment overlap option was not yet approved. No current requirement unrelated to migration was found. Removed the flag, literal output/validation code, migration tests, fixture parameter, and documentation. The helper now emits exactly one derived principal. Added a real SSH rejection test for a signed bare-account certificate; existing destination isolation and shared-domain tests pass. Updated the CLI audit. Validation: make -B build, make test, removed-flag CLI rejection checks, and diff --check all pass.

---
# Log: 2026-09-29T02:15:32Z Brian McCallister

Closed: Removed the requested flags and implementation paths, updated documentation and tests, and passed the full build/test suite.
