---
title: "Replace /tmp/foooo with proper tempfile location and cleanup in broker_test.go"
id: tpcj0xs7
created: 2025-10-22T16:09:07Z
updated: 2025-10-22T16:09:07Z
priority: medium
tags: [task]
---

In pkg/broker/broker_test.go:18, replace hardcoded /tmp/foooo with a proper temporary file that gets cleaned up after tests