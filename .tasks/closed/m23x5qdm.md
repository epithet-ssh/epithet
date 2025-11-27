---
title: "Implement 401 retry logic in broker: clear token, re-auth, retry cert request (limit retries to prevent infinite loops)"
id: m23x5qdm
created: 2025-10-25T19:46:17Z
updated: 2025-10-27T16:03:48Z
priority: critical
tags: [task]
---

When CA returns 401 Unauthorized: 1) Clear the current token, 2) Invoke auth plugin (which may use refresh token from state or do full re-auth), 3) Retry cert request with new token. Limit retries to prevent infinite loops with buggy auth plugins (suggest max 2-3 attempts). Use immediate retries (no backoff delay) - if there's a persistent issue, user will see the error and can retry the SSH connection. If retries exhausted, fail the Match and log error to stderr per epithet-48.