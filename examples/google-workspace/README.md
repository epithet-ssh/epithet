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

### 2. Configure the policy server

OIDC configuration lives on the **policy server**, not the client. Point it
at Google in `~/.epithet/policy.yaml`:

```yaml
policy:
  oidc:
    issuer: "https://accounts.google.com"
    client-id: "YOUR_CLIENT_ID.apps.googleusercontent.com"
    # client-secret: "YOUR_CLIENT_SECRET"   # only for Desktop apps
```

### 3. Configure the client

Create `~/.epithet/config.yaml` on each client:

```yaml
agent:
  ca-url: https://ca.corp.example.com
  name: default
```

The agent fetches the issuer and client ID from the CA's `/discovery`
endpoint at startup - there's no OIDC configuration on the client at all.

### 4. Configure SSH

Tag the hosts this profile should handle, then include epithet's
auto-generated config *after* those Tag lines, in `~/.ssh/config`
(requires **OpenSSH 9.4+** for `Tag`/`Match tagged`):

```
Host *.corp.example.com
    Tag epithet
Include ~/.epithet/run/*/ssh-config.conf
```

When you start `epithet agent`, it (re)generates a per-profile SSH config
gated by `Match tagged epithet`. Only hosts you tagged trigger
`epithet match`; everything else is untouched by epithet.

### 5. Start the broker

```bash
epithet agent
```

Or for more verbose output:

```bash
epithet agent -vv
```

The broker will run in the foreground. In production, you'd typically run it as a daemon (see `contrib/macos/` for a launchd example).

## Advanced configuration

### Multiple profiles

Run separate named profiles for different purposes (work vs personal,
different CAs). Each profile gets its own rundir, socket, and ssh Tag:

```bash
epithet agent --name work --ca-url https://work-ca.example.com
epithet agent --name personal --ca-url https://personal-ca.example.com
```

Tag hosts for each profile in `~/.ssh/config`:

```
Host *.work.example.com
    Tag epithet-work
Host *.personal.example.com
    Tag epithet-personal
Include ~/.epithet/run/*/ssh-config.conf
```

The single glob `Include` picks up every profile's generated config; no
per-profile SSH config editing is needed beyond the `Tag` lines.
