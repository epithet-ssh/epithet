---
yatl_version: 1
title: "Split inventory HTTP dispatch into logical handlers"
id: n4pge2o8
created: 2026-11-17T02:44:06Z
updated: 2026-11-17T02:44:06Z
author: Codex
priority: medium
tags:
- inventory
- refactor
---

## Problem

In `pkg/facts/server/inventory.go`, the records collection, individual record,
and audit routes all use `h.serve`, which passes them to a large `h.execute`
switch over paths and methods. Understanding an operation requires navigating
that shared dispatcher.

## Requested change

Break dispatch into logical handlers organized around the inventory resources
and operations. Keep shared request authentication, body handling, and error
responses coherent without duplicating them across handlers. Choose the handler
boundaries during implementation; no new routing framework is requested.

Preserve existing routes, methods, authentication and actor attribution,
creation-only enrollment/retry behavior, administrative write preconditions,
pagination, audit behavior, response bodies, headers, and status codes. This is
an organization refactor, not a provider protocol redesign.

## Validation

Run existing provider HTTP and enrollment tests, `make build`, and `make test`.
Add targeted coverage only for a concrete gap exposed by the refactor.

## Status

Deferred at the user's request during review of
[f1ljvrhn](../closed/f1ljvrhn.md). Do not implement as part of that enrollment
change.

---
# Log: 2026-11-17T02:44:06Z Codex

Filed the requested handler refactor. No implementation changes.
