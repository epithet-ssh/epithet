---
title: "Examine switching agent config from flat KV to CUE/YAML"
id: 0dn61afw
created: 2025-11-19T20:39:18Z
updated: 2025-11-19T20:39:26Z
priority: high
tags: [task]
---

Explore whether to switch the agent's simple flat config format (KVLoader in cmd/epithet) to CUE or YAML like the policy server uses.

Two angles to investigate:

1. **Direct switch**: Would CUE/YAML be better for agent config? Consider complexity vs flexibility tradeoff.

2. **Adapter approach**: Can we create an adapter from our flat KV format to CUE? Investigate how CUE's yaml.Extract or similar works - if we can provide a mapping/transformation, we could support both formats and have migration flexibility.

This is exploratory - may decide to keep the simple format if it's sufficient.