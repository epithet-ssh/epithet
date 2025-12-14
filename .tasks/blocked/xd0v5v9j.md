---
title: 'Broker - Match Short-Circuit: Use cached patterns to short-circuit non-matching hosts in Match(). File: pkg/broker/broker.go. Before cert request, check if host matches any cached pattern. If no match and have patterns, return not-handled immediately without HTTP request.'
id: xd0v5v9j
created: 2025-12-14T05:19:18.986354Z
updated: 2025-12-14T05:19:31.663896Z
author: Brian McCallister
priority: medium
tags:
- broker
- discovery
blocked_by:
- 1827k84k
---

---
## Log

---
# Log: 2025-12-14T05:19:18Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:19:27Z Brian McCallister

Implementation details:

In pkg/broker/broker.go Match() function:

Add pattern matching at the start:
  func (b *Broker) Match(conn policy.Connection) (*MatchResult, error) {
      // Short-circuit check
      if patterns := b.discovery.GetPatterns(); len(patterns) > 0 {
          if !matchesAnyPattern(conn.RemoteHost, patterns) {
              b.log.Debug("host does not match any discovery pattern, short-circuiting",
                  "host", conn.RemoteHost,
                  "patterns", patterns)
              return nil, ErrConnectionNotHandled
          }
      }
      // ... existing cert request flow
  }

Pattern matching function (reuse existing glob matching from pkg/broker):
  func matchesAnyPattern(host string, patterns []string) bool {
      for _, pattern := range patterns {
          if matched, _ := filepath.Match(pattern, host); matched {
              return true
          }
      }
      return false
  }

Behavior:
- If no cached patterns yet: proceed with request (will learn patterns from response)
- If have patterns but no match: return ErrConnectionNotHandled immediately (no HTTP)
- If have patterns and match: proceed with cert request
- Log when short-circuiting for debugging
---
# Log: 2025-12-14T05:19:31Z Brian McCallister

Added blocker: 1827k84k
