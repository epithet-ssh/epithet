---
title: "Handle agent creation failures: keep cert in store, fail Match with clear error about local system issue"
id: z9dq7yhq
created: 2025-10-25T20:03:10Z
updated: 2025-10-27T16:04:37Z
priority: high
tags: [task]
---

When certificate is valid but agent creation fails (socket directory permissions, disk space, etc): 1) Keep certificate in cert store (it's valid and may work on retry or for other connections), 2) Fail the Match with clear error explaining the agent creation problem (not a cert/auth issue), 3) User can fix local issue and retry. Agent creation failures are typically local system problems, not certificate/policy problems.