---
title: 'CA server: Shape-based request routing'
id: bxt3mhas
created: 2025-12-14T05:17:00.490708Z
updated: 2025-12-14T17:39:04.815556Z
author: Brian McCallister
priority: high
tags:
- protocol
- ca-server
blocked_by:
- qhfqkc0f
---

Handle hello vs cert requests based on request body shape.

File: pkg/caserver/caserver.go

Implementation:
- Make PublicKey and Connection optional pointers in request struct
- Empty body = hello request (validate token, return identity)
- Both present = cert request (existing flow)
- Otherwise = 400 Bad Request

Response types:
- HelloResponse: {identity: string}
- CreateCertResponse: {certificate, policy} (unchanged)

---
## Log

---
# Log: 2025-12-14T05:17:00Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:17:09Z Brian McCallister

Implementation details:
Request struct change:
  type CARequest struct {
      PublicKey  *sshcert.RawPublicKey `json:"publicKey,omitempty"`
      Connection *policy.Connection    `json:"connection,omitempty"`
  }

Routing logic in createCert():
  - If PublicKey == nil && Connection == nil -> hello request
  - If PublicKey != nil && Connection != nil -> cert request  
  - Otherwise -> 400 Bad Request (invalid combination)

Hello response:
  type HelloResponse struct { Identity string `json:"identity"` }

Cert response (existing, unchanged):
  type CreateCertResponse struct {
      Certificate sshcert.RawCertificate `json:"certificate"`
      Policy      policy.Policy          `json:"policy"`
  }

Error response:
  type ErrorResponse struct { Error string `json:"error"`; Message string `json:"message"` }

Flow:
1. Parse Authorization header
2. Parse JSON body into CARequest  
3. Route based on field presence
4. For hello: call policy server validation, return HelloResponse
5. For cert: existing flow, return CreateCertResponse
6. All responses get Link header (handled in Task 6)
---
# Log: 2025-12-14T05:17:13Z Brian McCallister

Added blocker: qhfqkc0f
---
# Log: 2025-12-14T17:35:51Z Brian McCallister

NOTE: Shape-based request handling still applies. The Authorization header now contains user token (from broker), not CA signature. Body shape determines hello vs cert request.