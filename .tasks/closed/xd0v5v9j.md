---
yatl_version: 0
title: 'Broker: Match short-circuit'
id: xd0v5v9j
created: 2025-12-14T05:19:18.986354Z
updated: 2025-12-25T03:35:33.674953Z
author: Brian McCallister
priority: medium
tags:
- broker
- discovery
---

Use cached patterns to short-circuit non-matching hosts in Match().

File: pkg/broker/broker.go

Implementation:
- Before cert request, check if host matches any cached pattern
- If no match and have patterns, return not-handled immediately
- Avoids HTTP request when host clearly won't match

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
---
# Log: 2025-12-25T03:21:39Z Brian McCallister

Removed blocker: 1827k84k

---
# Log: 2025-12-25T03:21:43Z Brian McCallister

Started working.

---
# Log: 2025-12-25T03:22:56Z Brian McCallister

Analyzed current code. The issue: shouldHandle() calls GetDiscovery() which makes hello request to CA every time. Need broker-level pattern caching to short-circuit before any network call.

---
# Log: 2025-12-25T03:26:04Z Brian McCallister

Implementation complete. Added:
- discoveryPatterns and discoveryMu to Broker struct for pattern caching
- Updated shouldHandle() to check cached patterns first (no network call)
- Added matchesAnyPattern() helper function
- Added updateDiscoveryPatterns() and refreshDiscoveryPatterns() methods
- Updated Match() to call refreshDiscoveryPatterns() after successful cert response
- Updated Inspect() to use cached patterns
- Updated test to reflect new behavior

---
# Log: 2025-12-25T03:26:11Z Brian McCallister

Closed: Implemented match short-circuit. shouldHandle() now checks cached discovery patterns first (no network call). Patterns are cached after successful cert response. Falls back to static patterns when no cache. All tests pass.

---
# Log: 2025-12-25T03:30:18Z Brian McCallister

Reopened.

---
# Log: 2025-12-25T03:30:33Z Brian McCallister

Started working.

---
# Log: 2025-12-25T03:30:33Z Brian McCallister

Reverting broker-level caching. The short-circuit should be in caclient: cache the discovery URL so subsequent GetDiscovery() calls skip the hello request.

---
# Log: 2025-12-25T03:35:28Z Brian McCallister

Implementation complete. Changes:
- Added discoveryURL cache to caclient.Client (protected by discoveryMu)
- GetDiscovery() now uses cached URL instead of making hello requests
- GetCert() caches the discovery URL from Link header
- Added SetDiscoveryURL() for testing
- Removed unused doHelloRequest()
- Updated caclient and broker tests

---
# Log: 2025-12-25T03:35:33Z Brian McCallister

Closed: Implemented match short-circuit in caclient. GetDiscovery() now uses cached discovery URL (learned from cert response Link headers) instead of making hello requests. This avoids unnecessary network calls when checking host patterns.
