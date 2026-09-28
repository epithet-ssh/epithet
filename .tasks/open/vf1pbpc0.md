---
yatl_version: 1
title: Investigate and likely remove accept-account-name migration support
id: vf1pbpc0
created: 2026-09-28T21:14:13.479015Z
updated: 2026-09-28T21:14:27.484334Z
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
