# Google Workspace authentication example

This example demonstrates how to use epithet with Google Workspace authentication.

## Prerequisites

1. Google Cloud project with OAuth2 credentials
2. Epithet CA and policy server running (see [Policy server guide](../../docs/policy-server.md))
3. SSH configured to use epithet

## Setup

### 1. Create OAuth2 credentials

Follow the [OIDC Setup Guide](../../docs/oidc-setup.md#google-workspace--google-cloud) to create OAuth2 credentials in Google Cloud Console.

**Recommended: Create a UWP app** (no client secret needed)
- Application type: Universal Windows Platform (UWP)
- Store package ID: Any valid string (e.g., "epithet-ssh-ca")
- You'll get: **Client ID** (e.g., `123456-abc.apps.googleusercontent.com`)

**Alternative: Create a Desktop app** (requires client secret)
- Application type: Desktop app
- You'll get: **Client ID** and **Client Secret**

### 2. Configure epithet

Create `~/.epithet/config.yaml`:

**For UWP apps (recommended):**
```yaml
agent:
  # CA server URL - host patterns are obtained from CA discovery
  ca-url: https://ca.corp.example.com

  # Authentication: Google Workspace via OIDC (no client secret needed)
  auth: epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID.apps.googleusercontent.com
```

**For Desktop apps:**
```yaml
agent:
  # CA server URL - host patterns are obtained from CA discovery
  ca-url: https://ca.corp.example.com

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

### 4. Start the broker

```bash
epithet agent
```

Or for more verbose output:

```bash
epithet agent -vv
```

The broker will run in the foreground. In production, you'd typically run it as a daemon.

## Advanced configuration

### Custom scopes

If your CA needs additional Google APIs:

```
auth epithet auth oidc \
  --issuer https://accounts.google.com \
  --client-id YOUR_CLIENT_ID \
  --scopes openid,profile,email,https://www.googleapis.com/auth/admin.directory.user.readonly
```

**Note**: Additional sensitive scopes may require Google app verification.

### Multiple brokers

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
