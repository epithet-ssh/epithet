---
title: 'Policy Server - Discovery Endpoint: Add discovery endpoint to built-in policy server. Files: cmd/epithet/policy.go, pkg/policyserver/discovery.go (new). GET /discovery/<version> endpoint with Bearer auth, returns matchPatterns JSON, content-addressable URL, Cache-Control immutable.'
id: sdjybkm6
created: 2025-12-14T05:19:36.589626Z
updated: 2025-12-14T05:19:50.678178Z
author: Brian McCallister
priority: medium
tags:
- policy-server
- discovery
blocked_by:
- mfcdv2zf
---

---
## Log

---
# Log: 2025-12-14T05:19:36Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:19:46Z Brian McCallister

Implementation details:

New file pkg/policyserver/discovery.go:

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
    // Parse Authorization header, validate token
    token := parseAuthHeader(r)
    if err := s.validateToken(token); err != nil {
        http.Error(w, "unauthorized", 401)
        return
    }
    
    // URL is content-addressable, version is in path
    // e.g., /discovery/abc123def456
    
    discovery := Discovery{
        MatchPatterns: s.config.MatchPatterns,
    }
    
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "max-age=31536000, immutable")
    json.NewEncoder(w).Encode(discovery)
}

type Discovery struct {
    MatchPatterns []string `json:"matchPatterns"`
}

In cmd/epithet/policy.go:

Add route for discovery:
  mux.HandleFunc("/discovery/", server.handleDiscovery)

Configuration:
  - Add matchPatterns []string to policy server config
  - Compute version hash: sha256(json.Marshal(patterns))[:12]
  - Use this hash when generating Link header URLs

The version in the URL path can be ignored for simple implementation - 
any request to /discovery/* returns current patterns. The URL changing 
triggers clients to refetch, which is the important behavior.
---
# Log: 2025-12-14T05:19:50Z Brian McCallister

Added blocker: mfcdv2zf
