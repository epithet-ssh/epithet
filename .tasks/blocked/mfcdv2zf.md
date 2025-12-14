---
title: 'Policy Server - Discovery Link Header: Policy server returns Link header with discovery URL on ALL responses. Files: pkg/policyserver/policyserver.go, cmd/epithet/policy.go. Set Link header, compute content-addressable URL from hash of patterns, include on success/error responses.'
id: mfcdv2zf
created: 2025-12-14T05:17:35.488965Z
updated: 2025-12-14T05:17:48.626627Z
author: Brian McCallister
priority: medium
tags:
- protocol
- policy-server
- discovery
blocked_by:
- 2xd411gq
---

---
## Log

---
# Log: 2025-12-14T05:17:35Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:17:45Z Brian McCallister

Implementation details:

Policy server sets Link header on ALL responses:
  w.Header().Set("Link", "<" + discoveryURL + ">; rel=\"discovery\"")

Discovery URL is content-addressable:
- Compute hash of match patterns: sha256(json.Marshal(patterns))[:12] or similar
- URL format: baseURL + "/discovery/" + hash
- Example: https://policy.example.com/discovery/abc123def456

Configuration:
- Policy server needs config for discovery base URL
- Policy server needs config for match patterns list
- These come from cmd/epithet/policy.go config

Key principle: Discovery URL is ALWAYS in HTTP Link header, NEVER in JSON body.
- Include on 200 OK responses
- Include on 401, 403, 422, 500 error responses
- CA will pass this header through to broker unchanged

JSON body is unchanged - just certParams and policy fields
---
# Log: 2025-12-14T05:17:48Z Brian McCallister

Added blocker: 2xd411gq
