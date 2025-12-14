---
title: Fix token encoding bug
id: v94qdww4
created: 2025-12-14T16:14:26.438529Z
updated: 2025-12-14T17:39:32.012730Z
author: Brian McCallister
priority: critical
tags:
- bug
- security
- protocol
---

CRITICAL BUG: Auth plugin raw bytes cast to string then JSON encoded was lossy.

Problem:
- Auth plugin outputs raw bytes to stdout
- Code did string(token) then JSON marshaled
- Invalid UTF-8 gets replaced with replacement char (data corruption)

Fix applied:
- Base64url encode immediately upon receipt from auth plugin
- Token is always base64url encoded throughout the system
- Only policy server decodes if it needs original bytes

---
## Log

---
# Log: 2025-12-14T16:14:26Z Brian McCallister

Created task.
---
# Log: 2025-12-14T16:14:38Z Brian McCallister

BUG DETAILS:

Current code path:
1. pkg/broker/auth.go:121 - token := stdout.Bytes()  // raw bytes from auth plugin
2. pkg/broker/auth.go:130 - h.token = string(token)  // cast to string (preserves bytes)
3. pkg/caclient/caclient.go:204 - json.Marshal(req)  // JSON encodes the Token string field
4. If token has invalid UTF-8 bytes, json.Marshal replaces them with \ufffd (U+FFFD)
5. DATA CORRUPTION - original bytes are lost, cannot be recovered

Why it works today (by accident):
- OIDC/JWT tokens are base64url strings (ASCII), so they survive JSON encoding
- But the protocol allows arbitrary bytes from auth plugins

FIX:
1. Store token as []byte internally in Auth struct
2. Base64url encode immediately when needed for transmission
3. For JSON body: use []byte field (Go auto-base64 encodes) OR encode to string first
4. For Authorization header: base64url encode to string

Files to fix:
- pkg/broker/auth.go - change token field from string to []byte
- pkg/broker/broker.go - update Token() usage
- pkg/caserver/caserver.go - CreateCertRequest Token field
- pkg/caclient/caclient.go - handle encoding

This overlaps with Task mc0 (Token Encoding Infrastructure) but is more urgent as a bug fix.
---
# Log: 2025-12-14T16:20:29Z Brian McCallister

UPDATED APPROACH (per Brian):

Instead of storing as []byte internally, immediately base64url encode upon receipt from auth plugin. Token is ALWAYS base64url encoded throughout the system - this is part of the protocol definition.

Flow:
1. Auth plugin outputs raw bytes to stdout
2. pkg/broker/auth.go IMMEDIATELY base64url encodes: 
   encoded := base64.RawURLEncoding.EncodeToString(stdout.Bytes())
3. Store as string (now safe - it's pure ASCII)
4. Use as string everywhere - JSON, headers, etc. all just work
5. Token is never decoded on broker/CA side - just passed through
6. Only policy server decodes if it needs the original bytes

Benefits:
- Simpler than storing []byte
- No risk of corruption anywhere in the pipeline  
- Protocol definition: 'token is always base64url encoded'
- String operations all safe (it's ASCII)
- JSON encoding just works

Code change is minimal - just add encoding at the source:
  pkg/broker/auth.go:130
  BEFORE: h.token = string(token)
  AFTER:  h.token = base64.RawURLEncoding.EncodeToString(token)
---
# Log: 2025-12-14T16:57:04Z Brian McCallister

Started working.
---
# Log: 2025-12-14T16:59:19Z Brian McCallister

Closed: Fixed: tokens are now base64url encoded immediately upon receipt from auth plugin. Added test for binary token preservation.