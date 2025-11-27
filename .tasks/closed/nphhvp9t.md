---
title: "Handle re-authentication when CA returns 403/Forbidden"
id: nphhvp9t
created: 2025-10-25T12:00:36Z
updated: 2025-10-27T16:03:48Z
priority: critical
tags: [task]
blocked_by: [e44282c7]
---

## Design

Use standard HTTP semantics for auth vs authz failures:

401 from CA/policy server:
- Means: Token is invalid, expired, or missing
- Broker action: Clear auth.token, call auth.Run() to re-authenticate, retry cert request with new token
- User experience: Brief pause while re-authenticating, then connection proceeds (or fails for other reason)

403 from CA/policy server:
- Means: Token is valid (user authenticated), but not authorized for this access
- May be temporary (approval workflow pending) or permanent (user lacks permission)
- Broker action: Keep token (still valid!), return policy server error message to user, do NOT auto-retry
- User experience: See error message explaining why (e.g., 'Approval required from ops-team'), can manually retry after approval granted

This distinction is important because:
- 403 might resolve later (approval granted) with same token - don't force re-auth
- 401 won't resolve without new token - must re-auth
- Follows standard HTTP semantics (401=authentication, 403=authorization)