---
yatl_version: 1
title: Remove arbitrary sshd reload command overrides from host enrollment
id: ym7anr2w
created: 2026-09-28T21:30:22.127751Z
updated: 2026-09-28T21:30:36.074002Z
author: Brian McCallister
priority: high
---

Remove `epithet host enroll --reload-command` and `--reload-arg`. The user explicitly requested eliminating these arbitrary command overrides: no concrete deployment requirement has been identified, and hypothetical nonstandard installations do not justify this public configuration surface.

Context: commit b183fcc9ce2671a9da6ff9316288afb20b48c9b6 introduced these flags while implementing task 930f5gpq. That task broadly says to allow enrollment-time overrides, but neither the task nor the implementation documentation identifies a concrete need for arbitrary reload executables. This is evidence of the recorded rationale, not proof of explicit user authorization or which model introduced it.

Scope and acceptance:
- Remove ReloadCommand and ReloadArgs from HostEnrollCLI, their parser flags, and the custom-command branch and related errors in SSHD settings resolution.
- Retain platform-native SSHD reload handling, configuration validation before activation, and existing rollback behavior.
- Update tests to exercise native platform commands through the existing injected runner/environment instead of requiring public override flags. Keep coverage of reload failure, rollback, and unchanged-configuration behavior.
- Remove these flags from documentation and the CLI flag audit; update the audit count and command inventory.
- Do not add compatibility aliases, deprecation paths, replacement override flags, or speculative service-manager support. Report unsupported platforms clearly using the existing error path, without suggesting removed flags.
- Run make build and make test.

This is deferred work. Other enrollment path/executable overrides and the separate match CLI-only proposal are outside this task.

---
# Log: 2026-09-28T21:30:22Z Brian McCallister

Created task.
