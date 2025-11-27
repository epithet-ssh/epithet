---
title: "Switch auth plugin protocol to fd 3 approach"
id: 2z1zsjbh
created: 2025-10-27T19:50:51Z
updated: 2025-10-27T20:06:09Z
priority: high
tags: [task]
---

Replace netstring-based protocol with simpler file descriptor approach. New protocol: stdin=state, stdout=token, fd3=new_state, stderr=errors. No encoding needed, state never touches disk, easy in all languages. Changes: update CLAUDE.md docs, remove pkg/netstr, update broker to use pipes, update examples.