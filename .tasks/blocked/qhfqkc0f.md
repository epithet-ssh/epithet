---
title: 'CA Server - Bearer Auth Header: Update CA server to accept token in Authorization header instead of body. File: pkg/caserver/caserver.go. Add parseAuthHeader() to extract Bearer token, remove Token from request body, return 401 if missing/invalid, pass token through to policy server unchanged.'
id: qhfqkc0f
created: 2025-12-14T05:16:43.284934Z
updated: 2025-12-14T05:16:54.546383Z
author: Brian McCallister
priority: high
tags:
- protocol
- ca-server
blocked_by:
- mc0d1e7n
---

---
## Log

---
# Log: 2025-12-14T05:16:43Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:16:50Z Brian McCallister

Implementation details:
- Parse 'Authorization: Bearer <token>' header
- func parseAuthHeader(r *http.Request) (string, error) - returns token string or error
- Token is kept as string (already base64url encoded), passed through to policy server as-is
- CA does NOT decode the token - it's opaque, just passes through
- Remove 'Token string' field from CreateCertRequest struct
- Return HTTP 401 Unauthorized if Authorization header missing or malformed
- Update pkg/caserver/caserver_test.go to send token in header
- Current code at line 60-64 has Token in body - remove it
---
# Log: 2025-12-14T05:16:54Z Brian McCallister

Added blocker: mc0d1e7n
