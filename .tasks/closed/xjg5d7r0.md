---
title: "Implement less strict netstring parser that tolerates whitespace for debugging"
id: xjg5d7r0
created: 2025-10-22T16:09:07Z
updated: 2025-10-27T15:29:47Z
priority: high
tags: [task]
---

The current auth plugin protocol uses the markdingo/netstring library which strictly rejects whitespace between netstrings. This makes debugging auth plugins difficult. We should implement a custom netstring parser that tolerates whitespace (spaces, tabs, \n, \r) between netstrings while still being strict about the netstring format itself. Location: README.md:85