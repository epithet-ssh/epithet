---
yatl_version: 1
title: Express policy certificate TTL in whole seconds
id: yenn28va
created: 2026-09-11T02:51:13.307026Z
updated: 2026-09-11T02:54:44.013070Z
author: Brian McCallister
priority: high
tags:
- api
---

Replace the policy response nanosecond ttl with integer ttlSeconds, as requested. Keep duration expressions in Writ and deployment configuration. Round evaluated durations down to whole seconds, reject values below one second, and validate the CA conversion against overflow. Preserve signing-time origin, independent authentication expiry and optional policy deadline. Update wire/API examples and migration guidance, verify boundary behavior, and run make build and make test.

---
# Log: 2026-09-11T02:51:13Z Brian McCallister

Created task.

---
# Log: 2026-09-11T02:52:13Z Brian McCallister

Started working.

---
# Log: 2026-09-11T02:54:44Z Brian McCallister

Closed: Changed policy response to integer ttlSeconds with explicit 1..9223372036 bounds and safe CA conversion to duration. Built-in policy converts duration defaults/rule results down to whole seconds and rejects results below one second; Writ syntax remains unchanged. Updated API 7 examples and migration documentation. Regression coverage verifies one-second TTL, maximum duration, overflow rejection, fractional/string/missing/legacy fields, deployment-default rounding, and unchanged authentication/deadline caps. make build, explicit go build ./cmd/epithet, full make test, and OpenAPI YAML/reference checks passed.
