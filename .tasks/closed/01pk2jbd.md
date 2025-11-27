---
title: "Extract common policy server logic to pkg/policyserver"
id: 01pk2jbd
created: 2025-11-16T18:03:20Z
updated: 2025-11-16T18:03:26Z
priority: high
tags: [task]
---

Create pkg/policyserver package with PolicyEvaluator interface, request/response types, and HTTP handler builder. Refactor dev policy server and AWS Lambda policy example to use this shared package.