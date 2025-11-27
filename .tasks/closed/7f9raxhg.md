---
title: "Fill in the rest of the %C connection fields in broker.go"
id: 7f9raxhg
created: 2025-10-22T16:09:07Z
updated: 2025-10-22T16:09:07Z
priority: high
tags: [task]
---

In pkg/broker/broker.go:30, the ConnectionInfo struct needs the remaining fields from the %C hash (local hostname, remote hostname, port, username, ProxyJump)