---
title: Multi-CA failover with circuit breaker
id: htbx21b7
created: 2025-11-29T23:57:17.446438Z
updated: 2025-11-30T01:18:24.436296Z
author: Brian McCallister
priority: high
tags:
- epic
- feature
---

---
## Log

---
# Log: 2025-11-29T23:57:17Z Brian McCallister

Created task.
---
# Log: 2025-11-29T23:57:50Z Brian McCallister

Full plan available at ~/.claude/plans/memoized-mapping-pelican.md

## Goal
Make epithet robust against CA failures by supporting multiple CA URLs with weighted priority and circuit breaker failover.

## Design Decisions (confirmed with user)
- **Priority**: Weighted round-robin. Higher weight = higher priority. Format: weight=N:https://url (default weight 100)
- **Circuit breaker**: Failed CAs disabled for configurable cooldown (default 10m), then re-enabled
- **Timeout**: Configurable per-request timeout (--ca-timeout, default 15s)
- **Cooldown**: Configurable via --ca-cooldown flag (default 10m)
- **Retry interaction**: 401 retry logic (3 attempts) is INDEPENDENT from failover. Failover only on connection/timeout errors.

## New Packages
1. pkg/cafailover - CA selection (weighted round-robin, circuit breaker)
   - config.go: CAEndpoint type, ParseCAURL/ParseCAURLs
   - circuitbreaker.go: IsAvailable, MarkFailed, MarkSuccess
   - selector.go: Select (returns next available CA URL)

2. pkg/multicaclient - Multi-CA wrapper with failover
   - client.go: GetCert with failover loop
   - errors.go: AllCAsUnavailableError

## CLI Changes (cmd/epithet/agent.go)
- --ca-url becomes []string (repeatable)
- Add --ca-timeout (default 15s)
- Add --ca-cooldown (default 10m)

## Broker Changes (pkg/broker/broker.go)
- Replace *caclient.Client with *multicaclient.Client
- Update New() signature to accept []CAEndpoint, timeout, cooldown
- Add AllCAsUnavailableError handling in Match()

## Circuit Breaker Triggers
YES: Connection errors, timeouts, 5xx (CAUnavailableError)
NO: 401 (InvalidTokenError), 403 (PolicyDeniedError), 4xx

## TODO
- Finalize weight encoding scheme in URL (current: weight=N:url)

## Critical Files
- pkg/broker/broker.go (main changes)
- cmd/epithet/agent.go (CLI flags)
- pkg/caclient/caclient.go (reference for error types)
---
# Log: 2025-11-29T23:59:31Z Brian McCallister

UPDATED: Simplified package structure per user feedback.

Instead of separate pkg/multicaclient, extend pkg/caclient directly with multi-CA support.

## Revised Package Structure
1. pkg/cafailover (NEW) - CA selection logic
   - config.go: CAEndpoint, ParseCAURL/ParseCAURLs
   - circuitbreaker.go: health tracking with cooldown
   - selector.go: weighted round-robin selection

2. pkg/caclient (EXTEND) - Add multi-CA support
   - Update Client struct to hold []CAEndpoint + Selector
   - Add GetCert failover loop
   - Add AllCAsUnavailableError
   - Add WithTimeout, WithCooldown options

No separate multicaclient package needed - cleaner design.
---
# Log: 2025-11-30T00:01:01Z Brian McCallister

FINAL: Everything in pkg/caclient, no new packages.

## Structure
All in pkg/caclient:
- config.go (new): CAEndpoint, ParseCAURL/ParseCAURLs  
- selector.go (new): weighted round-robin + circuit breaker (unexported)
- caclient.go: Update Client, add failover loop to GetCert
- errors.go: Add AllCAsUnavailableError

## Implementation Order
1. Add config.go + tests
2. Add selector.go + tests  
3. Update caclient.go + tests
4. Update broker.go New() signature
5. Update agent.go CLI flags
6. Update docs
---
# Log: 2025-11-30T00:35:40Z Brian McCallister

UPDATED: Using 'priority' instead of 'weight'.

## Terminology Change
- 'weight' implied proportional traffic distribution (weighted round-robin)
- 'priority' better describes strict ordering with failover

## Behavior
- Higher priority = tried first
- Round-robin only within same priority tier  
- Lower priority CAs used ONLY when all higher priority CAs are in circuit breaker
- This is primary/backup model, not load balancing

## URL Format
priority=N:https://ca.example.com/ (default priority 100)

## Future
See task gcn46n6z for potential weighted round-robin enhancement later.
---
# Log: 2025-11-30T00:37:10Z Brian McCallister

# Full Implementation Plan

## Overview

Add support for multiple Certificate Authorities with priority-based failover and circuit breaker to the epithet broker.

## Requirements

- **Multiple CA URLs**: Change `--ca-url` to be repeatable
- **Priority-based failover**: Format `priority=N:https://ca.example.com/`
  - Higher priority = tried first
  - Round-robin between CAs of same priority
  - Lower priority CAs only used when all higher priority CAs are in circuit breaker
  - Default priority: 100
- **Circuit breaker**: Failed/timed-out CAs disabled for ~10 minutes, then re-enabled
- **Configurable timeout**: Add `--ca-timeout` flag, default 15 seconds

## Changes to pkg/caclient

All new functionality goes in the existing `pkg/caclient` package.

### New Types

**config.go** (new file):
```go
type CAEndpoint struct {
    URL      string
    Priority int // Default 100, higher = tried first
}

func ParseCAURL(s string) (CAEndpoint, error)
func ParseCAURLs(urls []string) ([]CAEndpoint, error)
```

**selector.go** (new file):
```go
type selector struct {
    endpoints      []CAEndpoint
    mu             sync.Mutex
    disabledUntil  map[string]time.Time  // circuit breaker state
    cooldown       time.Duration
    tierIndices    map[int]int           // priority -> next index for round-robin
}

func newSelector(endpoints []CAEndpoint, cooldown time.Duration) *selector
func (s *selector) select() string
func (s *selector) markFailed(url string)
func (s *selector) markSuccess(url string)
```

**Selection algorithm:**
1. Group endpoints by priority, sort tiers descending (highest first)
2. For highest priority tier, round-robin through CAs
3. Skip CAs in circuit breaker cooldown
4. Only try lower priority tier if ALL higher priority CAs are unavailable
5. Return first available CA, or empty string if none

### Updated Client

**caclient.go**:
```go
type Client struct {
    endpoints  []CAEndpoint
    selector   *selector
    httpClient *http.Client
    timeout    time.Duration
    logger     *slog.Logger
}

func New(endpoints []CAEndpoint, options ...Option) (*Client, error)
func WithTimeout(d time.Duration) Option
func WithCooldown(d time.Duration) Option
```

**GetCert flow:**
1. selector.select() to get next CA URL
2. Call CA with timeout
3. On success: markSuccess(), return response
4. On circuit-breaker-triggering error: markFailed(), loop to try next CA
5. On non-failover error (401, 403): return immediately (don't failover)
6. If no CAs available: return AllCAsUnavailableError

**Circuit breaker triggers:**
- Connection errors (network unreachable, refused)
- Timeouts (context.DeadlineExceeded)
- Server errors (5xx via CAUnavailableError)

**NOT circuit breaker triggers:**
- InvalidTokenError (401) - token problem, not CA
- PolicyDeniedError (403) - policy decision, not CA
- InvalidRequestError (4xx) - client problem, not CA

**errors.go** - Add:
```go
type AllCAsUnavailableError struct {
    Message string
}
```

## File Changes

### cmd/epithet/agent.go
```go
type AgentCLI struct {
    Match      []string      
    CaURL      []string      // Now a slice
    Auth       string        
    CaTimeout  time.Duration // NEW: default 15s
    CaCooldown time.Duration // NEW: default 10m
}
```

### pkg/broker/broker.go
- Update New() signature: caEndpoints []CAEndpoint, caTimeout, caCooldown time.Duration
- Pass new options to caclient.New()
- Add error handling for AllCAsUnavailableError in Match()

### Test files
Update broker.New() calls in:
- pkg/broker/broker_test.go
- test/sshd/broker_test.go

## Configuration

Example config file:
```
ca-url https://ca-primary.example.com/
ca-url priority=100:https://ca-primary2.example.com/
ca-url priority=50:https://ca-backup.example.com/
ca-timeout 15s
ca-cooldown 10m
```

Defaults:
- --ca-timeout: 15s
- --ca-cooldown: 10m
- Default priority: 100

**Retry interaction:** 401 retry logic (3 attempts) is INDEPENDENT from failover. Failover only on connection/timeout errors.

## Implementation Sequence

### Phase 1: Extend caclient
1. Add pkg/caclient/config.go (CAEndpoint, ParseCAURL) + tests
2. Add pkg/caclient/selector.go (priority failover, circuit breaker) + tests
3. Update pkg/caclient/caclient.go for multi-CA support
4. Add AllCAsUnavailableError to pkg/caclient/errors.go
5. Update caclient tests

### Phase 2: Integration
1. Update cmd/epithet/agent.go CLI flags
2. Update pkg/broker/broker.go
3. Update broker tests
4. Add multi-CA integration test

### Phase 3: Documentation
1. Update CLAUDE.md
2. Update examples/epithet.config.example

## Test Strategy

**Unit tests:**
- URL parsing (with/without priority, invalid formats)
- Circuit breaker (available → failed → cooldown → available)
- Selector (priority ordering, round-robin within tier, all-unavailable case)
- Multi-CA client (success, failover, error type handling)

**Integration test (test/sshd/broker_multi_ca_test.go):**
- Two CA servers, one failing
- Circuit breaker recovery (use short cooldown)

**Mock servers:** Use httptest.Server for controllable CA behavior.

## URL Format

priority=N:https://ca.example.com/ where N is an integer (default 100, higher = tried first)

## Critical Files

| File | Change |
|------|--------|
| pkg/caclient/config.go | New: CAEndpoint, ParseCAURL |
| pkg/caclient/selector.go | New: priority failover, circuit breaker |
| pkg/caclient/caclient.go | Update for multi-CA support |
| pkg/caclient/errors.go | Add AllCAsUnavailableError |
| pkg/broker/broker.go | Update New() signature |
| cmd/epithet/agent.go | Slice flag, timeout/cooldown flags |