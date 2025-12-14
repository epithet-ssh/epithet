---
title: 'CA server: Accept Bearer auth from broker'
id: qhfqkc0f
created: 2025-12-14T05:16:43.284934Z
updated: 2025-12-14T17:38:51.162415Z
author: Brian McCallister
priority: high
tags:
- protocol
- ca-server
blocked_by:
- mc0d1e7n
---

Update CA server to accept user token in Authorization header from broker.

File: pkg/caserver/caserver.go

Implementation:
- Parse 'Authorization: Bearer <token>' header from incoming requests
- Extract base64url-encoded user token
- Remove Token field from request body struct
- Return HTTP 401 if Authorization header missing/malformed
- Pass token to policy server in request body (not header)

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
---
# Log: 2025-12-14T17:35:39Z Brian McCallister

DESIGN CHANGE: CA server has two different auth patterns now.

INBOUND (Broker -> CA):
- Authorization: Bearer <user_token_base64url>
- Body: {"publicKey": "...", "connection": {...}}

OUTBOUND (CA -> Policy Server):
- Authorization: Bearer <base64_sshsig_of_body>
- Body: {"token": "<user_token>", "connection": {...}}

CA flow:
1. Extract user token from inbound Authorization header
2. Build policy request body with token + connection
3. Sign the body bytes with CA private key
4. Send to policy server with signature as Bearer token
---
# Log: 2025-12-14T17:36:29Z Brian McCallister

CODE CHANGE NEEDED in pkg/ca/ca.go:RequestPolicy():

CURRENT (lines 145-164):
1. sig = c.Sign(token)
2. body = {token, signature, connection}
3. POST body

NEW:
1. body = {token, connection}  // no signature in body
2. bodyBytes = json.Marshal(body)
3. sig = c.Sign(string(bodyBytes))  // sign BODY, not token
4. req.Header.Set("Authorization", "Bearer " + sig)
5. POST body

Key change: CA signs the body bytes, not just the token. This binds signature to full request.