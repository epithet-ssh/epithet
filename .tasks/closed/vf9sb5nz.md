---
title: "Design policy configuration file format"
id: vf9sb5nz
created: 2025-11-16T08:15:04Z
updated: 2025-11-16T17:57:23Z
priority: high
tags: [task]
---

Define the structure for the policy config file: user identity mappings, host patterns, principals, certificate parameters. Should be simple text format (YAML/JSON/TOML) with clear documentation.

## Design

YAML-based config with 3 sections: server (OIDC issuer, CA pubkey, defaults), users (identity→principals+host_patterns mappings), default_policy (optional fallback). Uses filepath.Match for host patterns, coreos/go-oidc for token validation, ca.Verify for signature check. See docs/policy-config-design.md for complete spec with examples.

## Notes

COMPLETED: Final design uses simplified YAML/CUE format with oidc as string (issuer URL only). Structure: ca_public_key (string), oidc (string), users (map[string][]string), defaults (allow/expiration/extensions), hosts (per-host overrides). Updated docs/policy-config-design.md with complete spec, examples, and Go struct definitions. Ready for implementation.