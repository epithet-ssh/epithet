---
title: "Support ProxyJump by adding multiple certificates to per-connection agents"
id: vvy4hx3k
created: 2025-10-29T20:36:50Z
updated: 2025-10-29T20:43:17Z
priority: high
tags: [feature]
---

## Notes

FALSE ALARM - No work needed!

After detailed analysis, the per-connection agent design ALREADY handles ProxyJump correctly:

1. Each hop in a ProxyJump chain spawns a separate SSH process on local machine
2. Each process reads ~/.ssh/config and evaluates Match exec independently  
3. Each process gets its own %C hash (which includes %j - the ProxyJump value)
4. Each process uses its own IdentityAgent socket path (based on its unique %C)
5. epithet match is called separately for each hop with the correct target host

Example: ssh -J jumphost remote
- SSH Process 1: Match exec for jumphost -> agent at %C_jump with jumphost cert
- SSH Process 2: Match exec for remote -> agent at %C_remote with remote cert

Both processes authenticate independently with their respective certificates. The design is sound!

The %j field is still useful for:
- Logging/debugging (knowing which connections use jumps)
- Policy decisions (CA might care if connection uses ProxyJump)
- Future optimizations

But core functionality works without any code changes.