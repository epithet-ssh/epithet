---
title: Make inspect a subcommand of agent for config sharing
id: z1jvafyw
created: 2025-12-05T04:31:51.129430Z
updated: 2025-12-05T04:32:11.772608Z
author: Brian McCallister
priority: high
tags:
- feature
- cli
---

---
## Log

---
# Log: 2025-12-05T04:31:51Z Brian McCallister

Created task.
---
# Log: 2025-12-05T04:32:07Z Brian McCallister

## Problem

The inspect command needed CaURL and Match to derive the broker socket path (same hash logic as agent). The CUE resolver mapped flags based on command name:
- epithet inspect → looked for inspect.ca_url in config
- epithet agent → looked for agent.ca_url in config

Users had to duplicate config or always pass --ca-url to inspect.

## Solution

Made inspect a subcommand of agent so both use the same config section:
- epithet agent → starts the agent (default subcommand)
- epithet agent inspect → inspects broker state

This follows the existing pattern of epithet auth oidc.

## Files Modified

1. cmd/epithet/agent.go
   - AgentCLI now has subcommands: Start (default) and Inspect
   - Removed required:true from CaURL and Auth (validation moved to AgentStartCLI.Run())
   - Created AgentStartCLI with the existing start logic
   - References changed from a. to parent. in Run method

2. cmd/epithet/inspect.go
   - Renamed InspectCLI → AgentInspectCLI
   - Removed Match and CaURL fields (now inherited from parent AgentCLI)
   - Updated Run() to take parent *AgentCLI and use parent.CaURL/parent.Match

3. cmd/epithet/main.go
   - Removed standalone Inspect InspectCLI from cli struct

## Command Structure

epithet agent              → starts the agent (default, requires --ca-url and --auth)
epithet agent inspect      → inspects broker state (reads --ca-url/--match from config)

## Help Output Note

Kong shows 'agent start' in top-level help because it displays full paths to leaf commands. This is acceptable - the functionality works correctly with just 'epithet agent'.

## Config Example

agent:
  ca_url: https://ca.example.com
  match:
    - '*.example.com'
  auth: epithet auth oidc --issuer https://accounts.google.com --client-id XXX

Both commands now read from agent.ca_url and agent.match.
---
# Log: 2025-12-05T04:32:11Z Brian McCallister

Closed: Implemented: epithet agent inspect now reads ca-url/match from agent config section via kong parent-child flag inheritance
