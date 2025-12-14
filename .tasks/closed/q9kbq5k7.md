---
title: Add 421 Misdirected Request handling for CA/policy server responses
id: q9kbq5k7
created: 2025-12-14T04:07:03.039499Z
updated: 2025-12-14T04:22:47.232297Z
author: Brian McCallister
priority: medium
tags:
- feature
---

---
## Log

---
# Log: 2025-12-14T04:07:03Z Brian McCallister

Created task.
---
# Log: 2025-12-14T04:07:08Z Brian McCallister

421 Misdirected Request (RFC 9110): indicates the server is unable or unwilling to produce an authoritative response for the target URI. Use when CA/policy server doesn't handle a particular connection (e.g., host outside its domain).
---
# Log: 2025-12-14T04:07:13Z Brian McCallister

Distinct from existing codes: 401=token invalid (retry with fresh token), 403=policy denied (no retry), 421=wrong CA/not authoritative (client should try different CA or fall through)
---
# Log: 2025-12-14T04:12:22Z Brian McCallister

Decision: Use 422 Unprocessable Content instead of 421. Rationale: (1) 422 is descriptive ('can't process') not prescriptive ('try elsewhere'), (2) broker decides what to do with the response (fail match, let SSH fall through), (3) avoids HTTP/2 special handling concerns with 421, (4) widely recognized in REST APIs.
---
# Log: 2025-12-14T04:12:40Z Brian McCallister

Title should be updated to: 'Add 422 Unprocessable Content handling for CA/policy server responses'
---
# Log: 2025-12-14T04:17:39Z Brian McCallister

Started working.
---
# Log: 2025-12-14T04:17:44Z Brian McCallister

Starting implementation - adding ConnectionNotHandledError to caclient
---
# Log: 2025-12-14T04:18:15Z Brian McCallister

Completed caclient changes - now adding NotHandled helper to policyserver
---
# Log: 2025-12-14T04:18:36Z Brian McCallister

Completed policyserver changes - now adding broker error handling
---
# Log: 2025-12-14T04:19:01Z Brian McCallister

Code compiles - now adding tests
---
# Log: 2025-12-14T04:21:44Z Brian McCallister

All tests pass - now updating CLAUDE.md documentation
---
# Log: 2025-12-14T04:22:42Z Brian McCallister

Implementation complete: added ConnectionNotHandledError for 422, updated caclient, policyserver, broker, added tests, and updated CLAUDE.md
---
# Log: 2025-12-14T04:22:47Z Brian McCallister

Closed: Implemented 422 Unprocessable Content handling for CA/policy server responses
