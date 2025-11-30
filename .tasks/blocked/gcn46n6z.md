---
title: Consider weighted round-robin for CA load balancing
id: gcn46n6z
created: 2025-11-30T00:34:48.081228Z
updated: 2025-11-30T00:35:18.782835Z
author: Brian McCallister
priority: low
tags:
- idea
- future
blocked_by:
- htbx21b7
---

---
## Log

### 2025-11-30T00:34:48Z Brian McCallister

Created task.
### 2025-11-30T00:35:10Z Brian McCallister

Future enhancement to consider after priority-based failover is implemented.

## Context
The current multi-CA implementation (htbx21b7) uses priority-based failover:
- Higher priority CAs are always tried first
- Lower priority CAs only used when higher ones are in circuit breaker
- Round-robin only within same priority tier

## Weighted Round-Robin Alternative
Instead of strict priority ordering, distribute requests proportionally:
- weight=100 CA gets 2x traffic of weight=50 CA
- All CAs receive some traffic (no hot standby)

## Use Cases for Weighted
1. Canary deployments - send 10% traffic to new CA version
2. Load distribution - spread across multiple equivalent CAs
3. Reduce blast radius - no single CA gets 100% traffic
4. Capacity-based routing - bigger CA handles more

## Possible Implementation
- Add --ca-load-balance=weighted flag to switch algorithm
- Or add separate weight param: priority=100,weight=50:URL
- Keep priority for failover order, add weight for within-tier distribution

## Tradeoffs vs Priority
| Priority | Weighted |
|----------|----------|
| Simple mental model | More complex |
| Best latency (always use fastest) | Some requests go to slower CA |
| Backup only when needed | All CAs get traffic |
| Clear causality for debugging | Harder to trace |

## Decision
Start with priority (simpler, matches primary/backup use case).
Revisit weighted if canary/load-balancing needs arise.
### 2025-11-30T00:35:18Z Brian McCallister

Added blocker: htbx21b7
