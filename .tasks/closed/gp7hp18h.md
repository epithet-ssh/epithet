---
title: "Implement policy evaluation engine"
id: gp7hp18h
created: 2025-11-16T08:15:04Z
updated: 2025-11-16T19:23:35Z
priority: high
tags: [task]
blocked_by: [vf9sb5nz]
---

Given validated identity and connection details, look up user in policy config and determine: principals, host pattern match, certificate expiry, extensions. Return CertParams + Policy or 403 if denied.

## Notes

COMPLETED: Implemented tag-based authorization system. Users map to tags, tags map to principals per host/default. Algorithm: user has tags → check if requested principal allows any of user's tags → grant single principal (RemoteUser) in cert. Structure: users[identity]→tags, defaults.allow[principal]→allowed_tags, hosts[host].allow[principal]→allowed_tags. Evaluator checks set intersection for authorization. All tests passing. Created epithet-7r8 for future multi-principal cert issuance.