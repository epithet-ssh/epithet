# Authentication

Epithet uses external authentication plugins to obtain tokens for the CA server. This design allows epithet to work with any identity provider without needing to understand specific authentication protocols.

## Overview

The broker invokes authentication plugins when certificates need to be requested. Auth plugins follow a simple protocol:

- **stdin**: State from previous invocation (empty on first call)
- **stdout**: Authentication token (raw bytes)
- **fd 3**: New state to persist for next invocation (max 10 MiB)
- **stderr**: Human-readable messages and errors
- **Exit code**: 0 = success, non-zero = failure

## Built-in Auth Plugins

### OIDC/OAuth2 (`epithet auth oidc`)

Generic OIDC/OAuth2 authentication that works with Google Workspace, Okta, Azure AD, and any OIDC-compliant identity provider.

**Features:**
- Authorization code flow with PKCE
- Automatic token refresh
- Dynamic port selection (no configuration needed)
- Silent browser launch for authentication

**Usage:**

```bash
epithet agent \
  --match '*.example.com' \
  --ca-url https://ca.example.com \
  --auth "epithet auth oidc \
    --issuer https://accounts.google.com \
    --client-id 123456.apps.googleusercontent.com \
    --scopes openid,profile,email"
```

**Configuration:**

| Flag | Required | Description |
|------|----------|-------------|
| `--issuer` | Yes | OIDC issuer URL (e.g., `https://accounts.google.com`) |
| `--client-id` | Yes | OAuth2 client ID from your identity provider |
| `--client-secret` | No | OAuth2 client secret (optional if using PKCE) |
| `--scopes` | No | OAuth2 scopes (default: `openid,profile,email`) |

See [OIDC Setup Guide](./oidc-setup.md) for detailed instructions.

## Custom Auth Plugins

You can write custom authentication plugins in any language. They just need to follow the protocol:

### Example: Simple Token Plugin (Bash)

```bash
#!/bin/bash
# Read state from stdin (unused in this example)
state=$(cat)

# Get token somehow
token=$(my-auth-command)

# Output token to stdout
echo -n "$token"

# Output state to fd 3 (empty in this example)
echo -n "" >&3
```

### Example: Token with Refresh (Python)

```python
#!/usr/bin/env python3
import sys
import os
import json
import requests

# Read state from stdin
state_bytes = sys.stdin.buffer.read()
state = json.loads(state_bytes) if state_bytes else {}

# Check if we have a refresh token
if 'refresh_token' in state:
    # Refresh the token
    response = requests.post('https://auth.example.com/token', data={
        'grant_type': 'refresh_token',
        'refresh_token': state['refresh_token'],
        'client_id': 'client123',
    })
    data = response.json()
    access_token = data['access_token']
    new_refresh_token = data.get('refresh_token', state['refresh_token'])
else:
    # Perform initial authentication
    # (implementation depends on your auth system)
    access_token, new_refresh_token = do_initial_auth()

# Output access token to stdout
sys.stdout.buffer.write(access_token.encode())

# Output new state to fd 3
state_fd = os.fdopen(3, 'wb')
state_fd.write(json.dumps({
    'refresh_token': new_refresh_token
}).encode())
state_fd.close()
```

## Token Lifecycle

1. **First SSH connection:**
   - Broker has no token
   - Broker invokes auth plugin with empty stdin
   - Plugin performs full authentication (browser flow, etc.)
   - Plugin returns token and state
   - Broker uses token to request certificate from CA

2. **Subsequent connections (certificate expired):**
   - Broker invokes auth plugin with previous state on stdin
   - Plugin uses refresh token from state to get new access token
   - Plugin returns new token and updated state
   - Broker uses token to request certificate from CA

3. **CA returns 401 Unauthorized:**
   - Broker clears current token
   - Broker invokes auth plugin (may use refresh token from state)
   - Plugin returns fresh token
   - Broker retries certificate request

## Security Considerations

- **State never touches disk**: Broker stores state in memory only
- **10 MiB state limit**: Prevents memory exhaustion from buggy plugins
- **Tokens are opaque**: Broker doesn't parse or understand token format
- **Browser-based auth**: User authenticates in their browser, not in terminal
- **Refresh tokens**: Long-lived sessions without repeated browser auth

## Troubleshooting

### Browser doesn't open

The auth plugin launches your system's default browser. If nothing happens:
- Check your `BROWSER` environment variable
- Check that you have a browser installed
- Look for error messages in stderr

### "Authentication failed" errors

Check the auth plugin's stderr output for details. Common issues:
- Invalid client ID or secret
- Incorrect issuer URL
- User cancelled authentication in browser
- Network connectivity issues

### "Token refresh failed"

The refresh token may have expired or been revoked. This triggers a new full authentication flow. If it continues failing:
- Check that `--scopes` includes the scopes needed by your CA
- Verify the OAuth app is still active in your identity provider
- Check the CA server logs for token validation errors

## Provider-Specific Notes

### Google Workspace

- Issuer: `https://accounts.google.com`
- Supports OIDC discovery
- Refresh tokens valid until revoked or 6 months inactive
- See [OIDC Setup Guide](./oidc-setup.md) for OAuth app creation

### Okta

- Issuer: `https://your-domain.okta.com/oauth2/default`
- Supports OIDC discovery
- May require specific scopes for your CA

### Azure AD

- Issuer: `https://login.microsoftonline.com/{tenant-id}/v2.0`
- Supports OIDC discovery
- Refresh tokens have configurable lifetime

## Next Steps

- [OIDC Setup Guide](./oidc-setup.md) - Set up OAuth apps with Google, Okta, Azure AD
- [Example Configurations](../examples/) - Complete working examples
