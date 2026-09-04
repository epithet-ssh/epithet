---
yatl_version: 1
title: Retain epithet server as the easy-path composition unit
id: 0dgh3dd2
created: 2026-08-14T19:04:06.740001Z
updated: 2026-09-04T16:15:25.336962Z
author: Brian McCallister
priority: medium
---

Decision: retain `epithet server` as the supported one-command composition root while extracting inventory as a logical, separately deployable service. It may supervise CA, policy, and managed inventory child processes over private Unix sockets, or embed static inventory behind the same resolver contract. Policy must never be publicly routed. Advanced deployments may split the components for stronger workload and CA-key isolation. The implementation work is tracked by a5qt7g3m.

---
# Log: 2026-08-14T19:04:06Z Brian McCallister

Created task.

---
# Log: 2026-09-04T16:15:25Z Brian McCallister

Resolved the deployment decision: keep epithet server for the five-minute easy path; preserve component boundaries and permit separate deployment. Follow-up implementation is a5qt7g3m.

---
# Log: 2026-09-04T16:15:25Z Brian McCallister

Closed.
