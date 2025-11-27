---
title: "Expand policy matching beyond hostname to support per-user certificates"
id: r8zpcrbq
created: 2025-10-25T18:39:38Z
updated: 2025-11-19T20:46:42Z
priority: high
tags: [task]
---

Current limitation: Policy only matches on hostPattern, but different remote users connecting to the same host may need different certificates with different principals (e.g., deploy@server vs root@server).

Problem: If user SSHs to deploy@server.example.com (gets cert with principal 'deploy'), then later SSHs to root@server.example.com, the cert store lookup finds the existing cert (matches *.example.com) but it only has 'deploy' principal, not 'root', causing SSH to fail.

Solution: Expand Policy struct to match on additional connection fields beyond just hostname:
- remoteUser (e.g., 'deploy', 'root', '*')
- Potentially localUser, port, etc.

Design questions to resolve:
1. Should matching be AND logic (all fields must match) or pattern-based with wildcards per field?
2. Should lookup prefer exact matches first, then fall back to broader patterns? Or most-specific-match-wins?
3. How do we handle wildcard patterns in multiple dimensions?

This affects:
- pkg/policy/policy.go - Policy struct and Matches() method
- pkg/broker/certs.go - CertificateStore.Lookup() logic
- Policy server API - may need to return more granular policies