---
title: "Make CA server accept policy URL from environment variable"
id: 8qsf8n4x
created: 2025-11-09T20:37:20Z
updated: 2025-11-20T18:54:49Z
priority: critical
tags: [task]
blocked_by: [321mqp0t, yakp7qq9]
---

CA server currently has policy URL configured via flag. Need to also support POLICY_URL environment variable so it can be configured in Lambda without changing code.