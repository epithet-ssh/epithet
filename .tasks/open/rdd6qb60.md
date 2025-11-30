---
title: Update policy server to use LoadAndUnifyPaths for config unification
id: rdd6qb60
created: 2025-11-30T04:08:27.592917Z
updated: 2025-11-30T04:08:41.676075Z
author: Brian McCallister
priority: medium
tags:
- enhancement
---

---
## Log

### 2025-11-30T04:08:27Z Brian McCallister

Created task.
### 2025-11-30T04:08:41Z Brian McCallister

## Overview
The policy server currently uses `config.LoadFromFile[T]()` for single-file config loading.
Update it to use `config.LoadAndUnifyPaths()` to support multi-file config with CUE unification.

## Current State
- `cmd/epithet/policy.go` uses `config.LoadFromFile[policyserver.PolicyRulesConfig](c.ConfigFile)`
- Only loads a single config file specified by `--config-file` flag

## Target State
- Support glob patterns for policy config (e.g., `/etc/epithet/policy.d/*.yaml`)
- Unify multiple config files via CUE's `Value.Unify()`
- Conflict detection at load time (same field, different values = error)

## Implementation Steps

1. **Update PolicyServerCLI struct** in `cmd/epithet/policy.go`:
   - Change `ConfigFile string` to `ConfigPaths []string` (repeatable flag)
   - Or keep single `--config-file` but add `--config-dir` for glob pattern

2. **Update Run() method**:
   - Call `config.LoadAndUnifyPaths(patterns)` instead of `LoadFromFile`
   - Decode unified CUE value into `PolicyRulesConfig` struct
   - Example pattern:
     ```go
     unifiedVal, err := config.LoadAndUnifyPaths(c.ConfigPaths)
     if err != nil {
         return fmt.Errorf("failed to load policy config: %w", err)
     }
     var cfg policyserver.PolicyRulesConfig
     if err := unifiedVal.Decode(&cfg); err != nil {
         return fmt.Errorf("failed to decode policy config: %w", err)
     }
     ```

3. **Default paths** (optional):
   - Could default to `["/etc/epithet/policy.yaml", "/etc/epithet/policy.d/*.yaml"]`
   - Or require explicit paths like current behavior

## Use Cases Enabled
- Split policy into multiple files: base config, per-host overrides, per-team rules
- Environment-specific configs that layer on top of base
- Easier policy management in version control

## Reference
See `cmd/epithet/main.go` for example of LoadAndUnifyPaths usage with kong resolver.
