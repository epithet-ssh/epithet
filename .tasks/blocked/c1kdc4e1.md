---
yatl_version: 1
title: 'Two-tier discovery: public and authenticated endpoints'
id: c1kdc4e1
created: 2025-12-24T23:08:50.420228Z
updated: 2025-12-24T23:09:16.320617Z
author: Brian McCallister
priority: medium
tags:
- discovery
- protocol
blocked_by:
- sdjybkm6
- 1827k84k
---

---
# Log: 2025-12-24T23:08:50Z Brian McCallister

Created task.

---
# Log: 2025-12-24T23:08:54Z Brian McCallister

Added blocker: sdjybkm6

---
# Log: 2025-12-24T23:08:54Z Brian McCallister

Added blocker: 1827k84k

---
# Log: 2025-12-24T23:09:16Z Brian McCallister

## Specification

### Goal
Allow clients to bootstrap configuration from just the CA URL. Users only need epithet installed and the CA URL - everything else is discovered.

### Two Discovery Tiers

Both tiers use content-addressable URLs (/d/<hash>) for cache invalidation.

**Public Discovery:**
- Available without authentication
- Contains: OIDC issuer, client ID (enough to authenticate)
- Returned via Link header on unauthenticated/401 responses

**Authenticated Discovery:**
- Returned after successful authentication
- Contains: match patterns (derived from policy Hosts map keys)
- Client sends token in Authorization header; policy server may validate it (implementation choice, not spec requirement)

### Bootstrap Flow

1. Client has only CA URL
2. Client sends Hello() with no token
3. CA forwards to policy server with empty token
4. Policy server returns 401 + Link: </d/<public-hash>>
5. Client fetches /d/<public-hash> → gets OIDC config
6. Client authenticates
7. Client sends Hello() with token
8. Policy server returns 200 + Link: </d/<auth-hash>>
9. Client fetches /d/<auth-hash> → gets match patterns

### Response Formats

Public discovery:
  {"auth": {"type": "oidc", "issuer": "...", "client_id": "..."}}

Authenticated discovery:
  {"match_patterns": ["*.example.com", ...]}

### Protocol Requirements

1. CA must allow unauthenticated Hello() - parse body before checking auth header
2. Policy server returns different Link headers based on auth status
3. Discovery endpoints are content-addressable (Cache-Control: immutable)
4. Policy server serves /d/<hash> endpoint

### Design Decisions

- Auth on /d/<auth-hash>: Policy server's choice (built-in validates, not required by spec)
- Per-user discovery: Not required (built-in uses single hash, could vary)
- Match patterns source: Derive from Hosts map keys
- Public hash input: OIDC issuer + client_id

### Open Items

- Need to add client_id to OIDC config (currently only has issuer and audience)
