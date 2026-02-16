---
yatl_version: 1
title: Stream auth plugin stderr to match command for display
id: temcq9gy
created: 2026-01-28T16:32:38.554061Z
updated: 2026-02-16T22:31:48.215087Z
author: Brian McCallister
priority: high
tags:
- feature
blocked_by:
- m66az1s7
---

---
# Log: 2026-01-28T16:32:38Z Brian McCallister

Created task.

---
# Log: 2026-01-28T16:32:43Z Brian McCallister

Use case: device code OIDC flows where user has no local browser. Auth plugin needs to print 'Visit https://... and enter code ABC-123' and user must see it. Currently auth stderr goes to broker daemon (nowhere useful). Need to stream it back through RPC to match command which can write to stderr.

---
# Log: 2026-01-28T16:34:00Z Brian McCallister

Decision: Use gRPC server streaming. Match RPC returns stream of {stderr_chunk} messages during auth, then final {result}. Requires completing task m6 (switch to gRPC) first.

---
# Log: 2026-01-28T16:34:00Z Brian McCallister

Added blocker: m66az1s7

---
# Log: 2026-02-16T22:31:48Z Brian McCallister

Closed: Added e2e gRPC streaming test (Test_MatchStreamsUserOutput) that verifies fd 4 output flows through the full Match stream as UserOutput events. Fixed bug where getDiscoveryPatterns called auth.Run with nil userOutput, discarding fd 4 output during the initial auth triggered by shouldHandle. Now threads userOutput writer through shouldHandle → getDiscoveryPatterns → auth.Run.
