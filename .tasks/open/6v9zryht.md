---
title: Explore DAWG for host encoding
id: 6v9zryht
created: 2025-12-14T05:59:39.764919Z
updated: 2025-12-14T17:39:31.907945Z
author: Brian McCallister
priority: low
tags:
- discovery
- optimization
- future
blocked_by:
- xd0v5v9j
---

Explore packed trie (DAWG) for efficient host encoding in discovery data.

Reference: github.com/mckoss/dawg packed-trie format

Considerations:
- Use ARPA-style reversed hostnames for better suffix compression
- Port JavaScript implementation to Go
- Use case: thousands of specific hosts without nice glob patterns

---
## Log

---
# Log: 2025-12-14T05:59:39Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:59:50Z Brian McCallister

Reference implementation: https://github.com/mckoss/dawg

Packed Trie format (text-based, 7-bit ASCII):
- Nodes separated by ';'
- Node references in base-36
- Compact text representation suitable for JSON

ARPA-style hostname reversal for compression:
  server1.prod.example.com -> com.example.prod.server1
  server2.prod.example.com -> com.example.prod.server2
  
This turns common suffixes (.example.com) into common prefixes,
which tries compress well.

Discovery format extension:
{
  "matchPatterns": ["*.staging.example.com"],
  "hostTrie": "<packed-trie-string>"  // optional, for large host sets
}

Broker matching logic:
1. Check glob patterns first (fast for simple cases)
2. If no glob match, decode and search trie (O(hostname length))

Implementation steps:
1. Read mckoss/dawg JavaScript source
2. Port trie building to Go
3. Port packed encoding to Go
4. Port lookup/search to Go
5. Add to discovery response format
6. Update broker to handle trie lookups

This is a future optimization - basic discovery with glob patterns first.
---
# Log: 2025-12-14T05:59:55Z Brian McCallister

Added blocker: xd0v5v9j