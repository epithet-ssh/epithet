# Google Workspace Authentication Example

This example demonstrates how to use epithet with Google Workspace authentication.

## Prerequisites

1. Google Cloud project with OAuth2 credentials
2. Epithet CA server running (see [CA setup](../../docs/ca-setup.md))
3. SSH configured to use epithet

## Setup

### 1. Create OAuth2 Credentials

Follow the [OIDC Setup Guide](../../docs/oidc-setup.md#google-workspace--google-cloud) to create OAuth2 credentials in Google Cloud Console.

**Recommended: Create a UWP app** (no client secret needed)
- Application type: Universal Windows Platform (UWP)
- Store package ID: Any valid string (e.g., "epithet-ssh-ca")
- You'll get: **Client ID** (e.g., `123456-abc.apps.googleusercontent.com`)

**Alternative: Create a Desktop app** (requires client secret)
- Application type: Desktop app
- You'll get: **Client ID** and **Client Secret**

### 2. Configure Epithet

Create `~/.epithet/config.yaml`:

**For UWP apps (recommended):**
```yaml
agent:
  # CA server URL - host patterns are obtained from CA discovery
  ca_url: https://ca.corp.example.com

  # Authentication: Google Workspace via OIDC (no client secret needed)
  auth: epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID.apps.googleusercontent.com
```

**For Desktop apps:**
```yaml
agent:
  # CA server URL - host patterns are obtained from CA discovery
  ca_url: https://ca.corp.example.com

  # Authentication: Google Workspace via OIDC (client secret required)
  auth: epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID.apps.googleusercontent.com --client-secret YOUR_CLIENT_SECRET
```

Replace `YOUR_CLIENT_ID` (and optionally `YOUR_CLIENT_SECRET`) with your actual credentials from step 1.

**Note**: Host patterns (which hosts should use epithet) are obtained dynamically from the CA's discovery endpoint. The CA policy server determines which hosts are covered.

### 3. Configure SSH

Add to `~/.ssh/config` to include epithet's auto-generated config:

```
# Include epithet's auto-generated SSH config
Include ~/.epithet/run/*/ssh-config.conf
```

When you start `epithet agent`, it generates an SSH config that tells SSH to:
1. Run `epithet match` for all connections
2. The broker checks CA discovery patterns and returns non-zero for hosts that don't match
3. If epithet match succeeds, use the per-connection agent at `~/.epithet/run/<hash>/agent/%C`

### 4. Start the Broker

```bash
epithet agent
```

Or for more verbose output:

```bash
epithet agent -vv
```

The broker will run in the foreground. In production, you'd typically run it as a daemon.

## Usage

### First Connection

```bash
ssh user@server.corp.example.com
```

What happens:
1. SSH calls `epithet match`
2. Epithet match asks broker for a certificate
3. Broker has no token, so it invokes the auth plugin
4. **Your browser opens** to Google's login page
5. You authenticate with Google
6. Browser shows "Authentication successful"
7. Broker receives access token + refresh token
8. Broker requests certificate from CA using the token
9. CA validates token with its policy server
10. CA returns signed certificate
11. Broker creates per-connection agent with certificate
12. SSH uses certificate to connect

### Subsequent Connections

```bash
ssh user@another-server.corp.example.com
```

What happens:
1. SSH calls `epithet match`
2. Epithet match asks broker for a certificate
3. Certificate exists and is valid → returns immediately (fast!)
4. SSH uses existing certificate

OR if certificate expired:

1. SSH calls `epithet match`
2. Epithet match asks broker for a certificate
3. Certificate expired, broker invokes auth plugin
4. Auth plugin uses **refresh token** (no browser needed!)
5. Auth plugin returns new access token
6. Broker requests new certificate from CA
7. CA returns signed certificate
8. SSH proceeds with new certificate

This is fast (~100-200ms) because no browser interaction is needed.

## Token Lifecycle

- **Access tokens**: Short-lived (typically 1 hour)
- **Refresh tokens**: Long-lived (6 months of inactivity for Google)
- **Certificates**: Short-lived (2-10 minutes, configured by CA)

The broker automatically handles token refresh. You only see the browser on:
1. First connection of the day
2. After 6 months of inactivity (refresh token expired)
3. If you explicitly revoke access in Google settings

## Troubleshooting

### Browser doesn't open

Check that you have a default browser configured:
```bash
echo $BROWSER
```

Or set it explicitly:
```bash
export BROWSER=firefox
epithet agent
```

### "This app isn't verified"

This is normal for personal OAuth apps. Click:
1. **Advanced**
2. **Go to Epithet SSH CA (unsafe)**
3. **Allow**

To remove the warning, have your Google Workspace admin allowlist your OAuth client ID.

### "Authentication failed"

Check the broker logs (stderr) for details:
```bash
epithet agent -vv
```

Common issues:
- Wrong client ID
- OAuth app not enabled
- Network connectivity

### Token refresh fails

If you see repeated "Token refresh failed" messages:
1. Restart the broker (clears state)
2. Try connecting again (triggers new browser auth)
3. Check that your OAuth app is still active in Google Cloud Console

## Advanced Configuration

### Custom Scopes

If your CA needs additional Google APIs:

```
auth epithet auth oidc \
  --issuer https://accounts.google.com \
  --client-id YOUR_CLIENT_ID \
  --scopes openid,profile,email,https://www.googleapis.com/auth/admin.directory.user.readonly
```

**Note**: Additional sensitive scopes may require Google app verification.

### Multiple Brokers

Run separate brokers for different purposes (host patterns come from each CA's discovery endpoint):

**Work connections:**
```bash
epithet agent \
  --broker ~/.epithet/work-broker.sock \
  --agent-dir ~/.epithet/work-agent/ \
  --ca-url https://work-ca.example.com \
  --auth "epithet auth oidc --issuer https://accounts.google.com --client-id WORK_CLIENT_ID"
```

**Personal connections:**
```bash
epithet agent \
  --broker ~/.epithet/personal-broker.sock \
  --agent-dir ~/.epithet/personal-agent/ \
  --ca-url https://personal-ca.example.com \
  --auth "epithet auth oidc --issuer https://accounts.google.com --client-id PERSONAL_CLIENT_ID"
```

Update `~/.ssh/config` (optional `host` filter for optimization, since broker checks discovery patterns dynamically):
```
Match exec "epithet match --broker ~/.epithet/work-broker.sock --host %h --port %p --user %r --hash %C" host *.work.example.com
    IdentityAgent ~/.epithet/work-agent/%C

Match exec "epithet match --broker ~/.epithet/personal-broker.sock --host %h --port %p --user %r --hash %C" host *.personal.example.com
    IdentityAgent ~/.epithet/personal-agent/%C
```

## Security Notes

- **Tokens in memory only**: The broker never writes tokens to disk
- **Short-lived certificates**: Minimize blast radius if compromised
- **PKCE**: No client secret needed (can't be extracted from binary)
- **User control**: Users can revoke access anytime in Google account settings

## Next Steps

- Set up your CA server and policy server
- Configure SSH on all your client machines
- Set up monitoring and logging for the broker
- Consider running broker as a systemd service
