---
yatl_version: 1
title: Add SSH session detection for OIDC auth plugin
id: 6jm8vvtv
created: 2026-02-01T04:13:49.720155Z
updated: 2026-02-01T04:16:24.130994Z
author: Brian McCallister
priority: medium
tags:
- feature
- auth
- oidc
---

---
# Log: 2026-02-01T04:13:49Z Brian McCallister

Created task.

---
# Log: 2026-02-01T04:14:05Z Brian McCallister

## Goal

Allow auth plugins (especially OIDC) to know if the user is in an SSH session so they can adapt their behavior (e.g., skip browser.OpenURL() and just print the URL).

## Detection approach

Check SSH_CLIENT or SSH_CONNECTION environment variables in the match command. If either is set, the user is likely in an SSH session.

## Data flow

match command (detects SSH session via SSH_CLIENT/SSH_CONNECTION env)
    → gRPC MatchRequest.is_remote_session = true
    → grpc_server.Match() extracts flag
    → broker.MatchWithUserOutput(..., isRemoteSession)
    → auth.Run(..., isRemoteSession) sets EPITHET_REMOTE_SESSION=true
    → OIDC plugin checks env, skips browser.OpenURL()

## Files to modify

1. proto/brokerv1/broker.proto - add is_remote_session field
2. cmd/epithet/match.go - detect and send flag
3. pkg/broker/grpc_server.go - extract and pass flag
4. pkg/broker/broker.go - thread flag to Auth.Run
5. pkg/broker/auth.go - set EPITHET_REMOTE_SESSION env var
6. pkg/auth/oidc/oidc.go - check env, skip browser when remote

Full implementation plan saved in claude plans directory.

---
# Log: 2026-02-01T04:16:24Z Brian McCallister

## Updated approach: Use Device Authorization Grant (RFC 8628)

Instead of just printing the URL (which wouldn't help), switch to device flow for remote sessions:

1. Client POSTs to /device/authorization endpoint
2. Server returns device_code, user_code, verification_uri
3. Display: "Visit https://provider.com/device and enter code: ABCD-1234"
4. Client polls /token endpoint with device_code until user completes auth
5. User can authenticate on any device (phone, laptop, etc.)

This is the pattern used by gh, aws sso, gcloud, etc.

### Implementation notes

- Device authorization endpoint discoverable via /.well-known/openid-configuration
- golang.org/x/oauth2 has deviceauth package, or ~50 lines to implement manually
- OAuth client registration must have device flow enabled (provider-dependent)
- Most major providers (Google, Azure, Okta, Auth0, Keycloak) support both flows

### Revised OIDC plugin logic

if isRemoteSession {
    // Use device authorization grant
    deviceAuth() 
} else {
    // Use authorization code + PKCE with local browser
    browserAuth()
}
