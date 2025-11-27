---
title: "Implement OIDC token validation"
id: zbmxycp6
created: 2025-11-16T08:15:04Z
updated: 2025-11-16T18:17:29Z
priority: high
tags: [task]
blocked_by: [vf9sb5nz]
---

Create token validator that: 1) Parses JWT from request, 2) Validates signature against OIDC provider's JWKS, 3) Checks standard claims (exp, iss, aud), 4) Extracts identity (email/subject). Use coreos/go-oidc library.