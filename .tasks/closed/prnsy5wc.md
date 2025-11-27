---
title: "Split AWS Lambda examples into separate CA and policy server projects"
id: prnsy5wc
created: 2025-11-09T20:37:20Z
updated: 2025-11-20T18:54:49Z
priority: critical
tags: [feature]
---

Currently examples/aws-lambda contains both CA and policy server. Need to split into separate deployable projects so they can be deployed independently. This allows using the basic policy server example while keeping the CA server in the main repo.