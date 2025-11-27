---
title: "Pass connection details to auth command for mustache template rendering"
id: njhqwbcg
created: 2025-10-25T12:11:30Z
updated: 2025-10-25T12:11:30Z
priority: medium
tags: [task]
blocked_by: [e44282c7]
---

Currently auth.Run() is called with nil. We should pass MatchRequest fields (host, user, port, etc.) so auth commands can use mustache templates like {{host}} or {{user}} in their command line configuration.