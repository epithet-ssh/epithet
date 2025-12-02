---
title: Create unified pkg/config package with generic CUE loader
id: sz07a0ft
created: 2025-11-30T03:20:36.037559Z
updated: 2025-11-30T03:25:45.563809Z
author: Brian McCallister
priority: high
tags:
- feature
---

---
## Log

---
# Log: 2025-11-30T03:20:36Z Brian McCallister

Created task.
---
# Log: 2025-11-30T03:20:47Z Brian McCallister

Started working.
---
# Log: 2025-11-30T03:25:36Z Brian McCallister

Completed implementation:
- Created pkg/config/ with generic LoadFromFile[T]() function
- Created CLIConfig structs for CLI configuration
- Moved PolicyRulesConfig from policyserver/config to pkg/config
- Updated main.go with StructuredConfigLoader for kong
- Updated policy server and evaluator to use new config package
- Deleted old pkg/policyserver/config/ package
- Added comprehensive tests for the new config package
- Updated example config file to YAML format
---
# Log: 2025-11-30T03:25:45Z Brian McCallister

Closed: Implemented unified YAML/CUE configuration system
