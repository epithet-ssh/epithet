---
yatl_version: 0
title: Support glob patterns for policy server config loading
id: 5agrbv39
created: 2025-11-19T20:37:52Z
updated: 2025-12-26T21:59:55.113882Z
priority: high
tags:
- feature
blocked_by:
- 0dn61afw
---

Change config loading in pkg/policyserver/config/config.go to accept a glob pattern instead of a single file path. Use Go's filepath.Glob to expand the pattern, then load all matching files into the CUE context. This allows users to organize their policy config across multiple files (e.g., users.cue, hosts.cue, defaults.cue) which CUE will merge together.


---
# Log: 2025-12-26T21:59:55Z Brian McCallister

Closed: Already implemented via kongcue glob pattern loading in main.go - users can split policy config across multiple files in ~/.epithet/*.{cue,yaml,yml,json} which are unified by CUE
