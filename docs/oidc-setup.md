# OIDC authentication setup guide

This guide walks through setting up OAuth2/OIDC authentication with popular identity providers.

## Overview

Epithet's OIDC config lives on the **policy server**, not on individual clients. You create an OAuth2 application in your identity provider's console, then configure the policy server with the resulting **issuer URL** and **client ID** (and, for some providers, a **client secret**). The CA advertises this configuration to clients via a `Link` header on its root response, so `epithet agent` needs no OIDC configuration of its own — just `--ca-url`.

**Important**: Epithet uses PKCE (Proof Key for Code Exchange), so the client secret is optional for most providers. Where a provider requires one anyway, it goes in the policy server's config, not on the client — the secret never appears in a broker or ssh config.

Scopes are not configurable: epithet always requests `openid profile email`. Nothing in epithet consumes any other claim, so there is nothing to add here.

## Google Workspace / Google Cloud

### Step 1: create OAuth2 credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Select or create a project
3. Navigate to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. Choose **Application type** - see options below
6. Enter a name (e.g., "Epithet SSH CA")
7. Click **Create**

**Application Type Options:**

**Option A: Universal Windows Platform (UWP)** *(Recommended - No client secret needed)*
- Choose **"Universal Windows Platform (UWP)"**
- Fill in **Store package ID** with any valid string (e.g., "epithet-ssh-ca")
- **Advantage**: Works with PKCE only, no client secret required
- **Note**: Despite the name, this works for any CLI tool on any platform

**Option B: Desktop app** *(Requires client secret)*
- Choose **"Desktop app"**
- **Advantage**: Standard Desktop app type
- **Disadvantage**: Google requires client secret even with PKCE
- You'll need to configure `client-secret` on the policy server

### Step 2: configure redirect URI

Both app types automatically accept `http://localhost` with any port. No manual configuration needed!

### Step 3: note your credentials

You'll see a dialog with:
- **Client ID**: Something like `123456-abc.apps.googleusercontent.com`
- **Client secret**:
  - **UWP apps**: Not needed (can ignore)
  - **Desktop apps**: Required - note this value

### Step 4: configure the policy server

In `~/.epithet/policy.yaml` (or wherever your policy config lives):

```yaml
policy:
  oidc:
    issuer: "https://accounts.google.com"
    client-id: "YOUR_CLIENT_ID.apps.googleusercontent.com"
    # client-secret: "YOUR_CLIENT_SECRET"   # only for Desktop apps
```

Config-file keys for these CLI-backed scalars are kebab-case (derived from
the flag names — `client-id`, not `client_id`); see the casing note in the
[policy server guide](./policy-server.md#configuration-structure).

Or via flags:

```bash
epithet policy \
  --ca-pubkey ... \
  --oidc-issuer https://accounts.google.com \
  --oidc-client-id YOUR_CLIENT_ID.apps.googleusercontent.com
```

Clients need nothing beyond `--ca-url` — the broker discovers the issuer and client ID from the CA's root response at startup.

### Step 5: first authentication

When you first connect via SSH:
1. Your browser will open automatically
2. You may see "This app isn't verified" (normal for personal OAuth apps)
3. Click "Advanced" → "Go to Epithet SSH CA (unsafe)"
4. Grant the requested permissions
5. Browser will show "Authentication successful"
6. Return to your terminal - SSH connection proceeds

Subsequent connections reuse the refresh token automatically (no browser needed).

### Google Workspace admin allowlist (optional)

If you're using a shared OAuth app or want to skip the "unverified" warning:

1. Go to [Google Admin Console](https://admin.google.com)
2. Navigate to **Security** → **API controls** → **App access control**
3. Click **Configure** under "Trusted apps"
4. Add your OAuth client ID
5. Users in your domain won't see the warning

---

## Okta

### Step 1: create OAuth2 application

1. Log in to your [Okta Admin Console](https://your-domain.okta.com/admin)
2. Navigate to **Applications** → **Applications**
3. Click **Create App Integration**
4. Choose **OIDC - OpenID Connect**
5. Choose **Application type**: **Native Application**
6. Click **Next**

### Step 2: configure application

- **App integration name**: Enter "Epithet SSH CA"
- **Grant type**: Check **Authorization Code** and **Refresh Token**
- **Sign-in redirect URIs**: Add `http://localhost` (no port, no path)
  - Epithet lets its OAuth2 client library (`oauth2cli`) pick a free loopback
    port at random for each authentication and redirects to
    `http://localhost:<port>`. Per
    [RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3), Okta
    treats a registered `http://localhost` redirect URI as a wildcard-port
    loopback redirect, so a single entry with no port covers every port
    epithet might choose - no need to register a fixed list of ports
- **Sign-out redirect URIs**: Leave empty
- **Controlled access**: Choose appropriate assignment (e.g., "Allow everyone in your organization to access")
- Click **Save**

### Step 3: note your credentials

After creating the app:
- **Client ID**: Copy this value
- **Client secret**: Not needed (PKCE handles authentication)

### Step 4: find your issuer URL

Your Okta issuer URL depends on your authorization server:

- **Default**: `https://your-domain.okta.com/oauth2/default`
- **Custom**: `https://your-domain.okta.com/oauth2/your-auth-server`

To verify:
1. Go to **Security** → **API** → **Authorization Servers**
2. Find your authorization server
3. Copy the **Issuer URI**

### Step 5: configure the policy server

```bash
epithet policy \
  --ca-pubkey ... \
  --oidc-issuer https://your-domain.okta.com/oauth2/default \
  --oidc-client-id YOUR_CLIENT_ID
```

Okta supports `openid`, `profile`, `email`, and `offline_access` (refresh tokens); these are the same scopes epithet already requests.

---

## Azure AD / Microsoft identity platform

### Step 1: register application

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Enter **Name**: "Epithet SSH CA"
5. Choose **Supported account types**:
   - **Single tenant**: Only your organization
   - **Multi-tenant**: Any Azure AD organization
6. **Redirect URI**: Select **Public client/native (mobile & desktop)**, enter `http://localhost`
7. Click **Register**

### Step 2: configure authentication

1. In your app, go to **Authentication**
2. Under **Advanced settings** → **Allow public client flows**: Select **Yes**
3. Click **Save**

### Step 3: note your credentials

- **Application (client) ID**: Copy this from the Overview page
- **Directory (tenant) ID**: Also from the Overview page
- **Client secret**: Not needed for public clients

### Step 4: configure the policy server

```bash
epithet policy \
  --ca-pubkey ... \
  --oidc-issuer https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0 \
  --oidc-client-id YOUR_CLIENT_ID
```

Replace:
- `YOUR_TENANT_ID` with your Directory (tenant) ID
- `YOUR_CLIENT_ID` with your Application (client) ID

### Common tenant IDs

- **Specific tenant**: Use your tenant ID (e.g., `12345678-1234-1234-1234-123456789012`)
- **Organizations**: Use `organizations` (any Azure AD tenant)
- **Common**: Use `common` (any Azure AD or personal Microsoft account)

---

## Generic OIDC provider

If your provider supports OIDC discovery (most modern providers do), you can use the generic configuration:

### Step 1: create OAuth2 application

Follow your provider's documentation to create an OAuth2 application with:
- **Application type**: Native, Desktop, or Public Client
- **Grant type**: Authorization Code
- **PKCE**: Enabled (required)
- **Redirect URI**: `http://localhost` with no fixed port - epithet's OAuth2
  client library (`oauth2cli`) picks a free loopback port at random for each
  authentication. Register a loopback redirect that allows any port
  (`http://127.0.0.1` or `http://localhost`, per
  [RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)); most
  modern providers, including Okta and Google, support this

### Step 2: find OIDC discovery endpoint

Most providers expose OIDC discovery at:
```
https://your-provider.com/.well-known/openid-configuration
```

The issuer URL is usually the base URL (without `/.well-known/...`).

### Step 3: configure the policy server

```bash
epithet policy \
  --ca-pubkey ... \
  --oidc-issuer https://your-provider.com \
  --oidc-client-id YOUR_CLIENT_ID
```

---

## Client setup

Once the policy server is configured, clients need only the CA URL:

```bash
epithet agent --ca-url https://ca.example.com --name work
```

Then tag the hosts this profile should handle and include the generated config, in `~/.ssh/config`:

```ssh_config
Host *.example.com
    Tag epithet-work
Include ~/.epithet/run/*/ssh-config.conf   # must come after Tag lines
```

`Tag`/`Match tagged` requires **OpenSSH 9.4+** (macOS Sequoia and Ubuntu 24.04 both qualify).

## Troubleshooting

### "Failed to create OIDC provider"

- Check that the policy server's `--oidc-issuer` URL is correct
- Verify your provider supports OIDC discovery
- Try accessing `{issuer}/.well-known/openid-configuration` in a browser

### "Authentication failed" in browser

- Verify the policy server's `--oidc-client-id` is correct
- Check that the OAuth app is enabled in your provider
- Ensure the redirect URI is registered as a loopback wildcard-port URI (`http://localhost` or `http://127.0.0.1`, with no fixed port)

### Browser opens but shows error

- **"redirect_uri_mismatch"**: Your OAuth app's redirect URI must allow `http://localhost` (or `http://127.0.0.1`) with **any** port - epithet picks a free port at random each time, so a single fixed-port entry will eventually stop matching
- **"invalid_client"**: Double-check the client ID configured on the policy server
- **"unauthorized_client"**: Your OAuth app may not be configured for authorization code flow or PKCE

### Token refresh fails repeatedly

- Refresh token may have expired (Google: 6 months inactive)
- OAuth app may have been disabled or deleted
- User may have revoked access
- Solution: restart `epithet agent` to force full re-authentication (refresh state is memory-only)

### "This app isn't verified" (Google)

This is normal for personal OAuth apps. Options:
1. Click "Advanced" → "Go to {app name} (unsafe)" to proceed
2. Have your Google Workspace admin allowlist the app
3. Submit your app for Google verification (if you have many users)

## Next steps

- [Authentication overview](./authentication.md) - How the in-process OIDC flow works
- [Policy server guide](./policy-server.md) - Full policy server configuration
- [Example configurations](../examples/) - Complete working examples
