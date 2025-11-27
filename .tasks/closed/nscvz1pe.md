---
title: "Implement auth state storage (map of user identity → state blob)"
id: nscvz1pe
created: 2025-10-22T16:09:07Z
updated: 2025-10-22T16:09:07Z
priority: critical
tags: [task]
---

## Design

Auth type already implements state cycling correctly in auth.go:127-171. Task is to change broker from single 'auth *Auth' to 'auths map[string]*Auth' where key is user identity (probably LocalUser from MatchRequest). Need method like GetOrCreateAuth(userID) that returns *Auth for that user.