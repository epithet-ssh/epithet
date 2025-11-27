---
title: "Make broker socket path configurable to support multiple concurrent brokers"
id: e31rc0rr
created: 2025-10-25T18:57:24Z
updated: 2025-10-27T16:07:48Z
priority: high
tags: [task]
---

Currently the broker socket path defaults to ~/.epithet/broker.sock, which prevents running multiple brokers concurrently. Need to make this configurable.

Use case: User may want separate brokers for work vs personal, different CA servers, different match patterns, etc.

Example setup:
- Work broker: --broker-sock ~/.epithet/work-broker.sock --match *.work.example.com
- Personal broker: --broker-sock ~/.epithet/personal-broker.sock --match *.personal.example.com

Changes needed:
1. epithet agent command: Already has default, keep it configurable via flag/config
2. epithet match command: Add --broker flag to specify which broker to connect to (currently hardcoded in match.go)
3. Update SSH config examples to show broker selection

Note: Agent socket directory is already configurable via --agent-sock-dir flag ✓

Files to update:
- cmd/epithet/match.go - Add --broker flag, use instead of hardcoded path
- cmd/epithet/agent.go - Already has --broker-sock flag ✓
- SSH config examples in docs
