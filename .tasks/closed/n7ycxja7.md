---
title: "Parse SSH certificate ValidBefore field to get actual expiry time instead of hardcoding 5 minutes"
id: n7ycxja7
created: 2025-10-25T20:05:43Z
updated: 2025-10-27T16:03:16Z
priority: critical
tags: [task]
---

Currently broker.Match() and ensureAgent() hardcode 5-minute expiry with TODO comments. Need to parse the SSH certificate to extract ValidBefore timestamp and use that for expiration tracking in agentEntry and PolicyCert. The golang.org/x/crypto/ssh library provides this functionality. Certificate is the source of truth for expiry time.