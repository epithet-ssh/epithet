---
title: 'CA Server - Pass Through Link Header: CA reads Link header from policy server response and copies it to CA response. File: pkg/caserver/caserver.go. No caching, no discovery endpoint - just forward the header on all response types (hello, cert, errors).'
id: eg21yfrr
created: 2025-12-14T05:17:53.520494Z
updated: 2025-12-14T17:35:51.470104Z
author: Brian McCallister
priority: medium
tags:
- protocol
- ca-server
- discovery
blocked_by:
- bxt3mhas
- mfcdv2zf
---

---
## Log

---
# Log: 2025-12-14T05:17:53Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:18:00Z Brian McCallister

Implementation details:

After calling policy server, read Link header from response:
  linkHeader := policyResp.Header.Get("Link")
  if linkHeader != "" {
      w.Header().Set("Link", linkHeader)
  }

CA does NOT:
- Parse or interpret the Link header
- Cache discovery data
- Serve a discovery endpoint
- Decode or modify the URL

CA just passes through whatever Link header the policy server returned.

This applies to ALL responses:
- Hello responses (200)
- Cert responses (200)  
- Error responses (401, 403, 422, 500)

The policy server HTTP response object needs to be accessible to read the header.
May need to adjust how pkg/ca/ca.go returns the policy response to include headers.
---
# Log: 2025-12-14T05:18:05Z Brian McCallister

Added blocker: bxt3mhas
---
# Log: 2025-12-14T05:18:05Z Brian McCallister

Added blocker: mfcdv2zf
---
# Log: 2025-12-14T17:35:51Z Brian McCallister

NOTE: Link header passthrough is unaffected by auth design change. CA still reads Link from policy response and copies to its response.
