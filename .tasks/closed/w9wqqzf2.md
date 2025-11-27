---
title: "Add comprehensive concurrency documentation and fix race conditions"
id: w9wqqzf2
created: 2025-10-25T15:43:03Z
updated: 2025-10-25T15:43:08Z
priority: high
tags: [task]
---

Add locking invariants documentation to Broker, Agent, Auth, and CertificateStore. Remove unused Agent.lock field. Fix race condition in sshd test helper by wrapping bytes.Buffer with thread-safe safeBuffer. All code now passes race detector tests.