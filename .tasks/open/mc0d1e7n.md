---
title: 'Token Encoding Infrastructure: Add base64url encoding for tokens using base64.RawURLEncoding. Files: pkg/caclient/caclient.go, pkg/broker/auth.go. Token stored as raw bytes, encoded only when sending in Authorization header.'
id: mc0d1e7n
created: 2025-12-14T05:16:30.485783Z
updated: 2025-12-14T16:14:52.370822Z
author: Brian McCallister
priority: high
tags:
- protocol
- foundation
blocked_by:
- v94qdww4
---

---
## Log

---
# Log: 2025-12-14T05:16:30Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:16:37Z Brian McCallister

Implementation details:
- Use base64.RawURLEncoding (no padding, URL-safe alphabet: A-Z, a-z, 0-9, -, _)
- RFC 4648 §5 compliant, fits within RFC 6750 token68 grammar for Bearer tokens
- Add helper function: func encodeToken(token []byte) string { return base64.RawURLEncoding.EncodeToString(token) }
- Token is stored as raw []byte internally, only encoded when placed in Authorization header
- This is the foundation task - all other protocol tasks depend on this
---
# Log: 2025-12-14T16:14:52Z Brian McCallister

Added blocker: v94qdww4
