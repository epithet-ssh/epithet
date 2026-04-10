# OIDC authentication setup guide

This guide walks through setting up OAuth2/OIDC authentication with popular identity providers.

## Overview

To use `epithet auth oidc`, you need to create an OAuth2 application in your identity provider's console. This gives you a **client ID** and optionally a **client secret** to use with epithet.

**Important**: Epithet uses PKCE (Proof Key for Code Exchange), so the client secret is optional. For most providers, you can create a "desktop app" or "native app" which doesn't require a client secret.

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
- You'll need to include `--client-secret` in your epithet configuration

### Step 2: configure redirect URI

Both app types automatically accept `http://localhost` with any port. No manual configuration needed!

### Step 3: note your credentials

You'll see a dialog with:
- **Client ID**: Something like `123456-abc.apps.googleusercontent.com`
- **Client secret**: 
  - **UWP apps**: Not needed (can ignore)
  - **Desktop apps**: Required - note this value

### Step 4: configure epithet

**For UWP apps (no client secret needed):**

```bash
epithet agent \
  --ca-url https://ca.example.com \
  --auth "epithet auth oidc \
    --issuer https://accounts.google.com \
    --client-id YOUR_CLIENT_ID.apps.googleusercontent.com"
```

**For Desktop apps (client secret required):**

```bash
epithet agent \
  --ca-url https://ca.example.com \
  --auth "epithet auth oidc \
    --issuer https://accounts.google.com \
    --client-id YOUR_CLIENT_ID.apps.googleusercontent.com \
    --client-secret YOUR_CLIENT_SECRET"
```

**Or in a config file (`~/.epithet/config.yaml`):**

UWP apps:
```yaml
agent:
  ca-url: https://ca.example.com
  auth: "epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID.apps.googleusercontent.com"
```

Desktop apps:
```yaml
agent:
  ca-url: https://ca.example.com
  auth: "epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID.apps.googleusercontent.com --client-secret YOUR_CLIENT_SECRET"
```

### Step 5: first authentication

When you first connect via SSH:
1. Your browser will open automatically
2. You may see "This app isn't verified" (normal for personal OAuth apps)
3. Click "Advanced" → "Go to Epithet SSH CA (unsafe)"
4. Grant the requested permissions
5. Browser will show "Authentication successful"
6. Return to your terminal - SSH connection proceeds

Subsequent connections use the refresh token automatically (no browser needed).

### Google Workspace admin allowlist (optional)

If you're using a shared OAuth app or want to skip the "unverified" warning:

1. Go to [Google Admin Console](https://admin.google.com)
2. Navigate to **Security** → **API controls** → **App access control**
3. Click **Configure** under "Trusted apps"
4. Add your OAuth client ID
5. Users in your domain won't see the warning

### Scopes

Default scopes (`openid,profile,email`) are usually sufficient. Your CA server will receive the ID token for validation.

If your CA needs additional Google APIs, add them to `--scopes`:

```bash
--scopes openid,profile,email,https://www.googleapis.com/auth/admin.directory.user.readonly
```

**Note**: Additional scopes may require app verification if you exceed 100 users.

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
- **Sign-in redirect URIs**: Add `http://localhost:8080/callback`
  - Okta doesn't support wildcard ports, so also add:
  - `http://localhost:8081/callback`
  - `http://localhost:8082/callback`
  - (epithet will try these ports in order)
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

### Step 5: configure epithet

```bash
epithet agent \
  --ca-url https://ca.example.com \
  --auth "epithet auth oidc \
    --issuer https://your-domain.okta.com/oauth2/default \
    --client-id YOUR_CLIENT_ID"
```

### Scopes

Default scopes work for most cases. Okta supports:
- `openid` (required)
- `profile` (user profile info)
- `email` (email address)
- `offline_access` (refresh tokens - automatically included by epithet)

Custom scopes can be defined in your authorization server configuration.

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

### Step 4: configure epithet

```bash
epithet agent \
  --ca-url https://ca.example.com \
  --auth "epithet auth oidc \
    --issuer https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0 \
    --client-id YOUR_CLIENT_ID"
```

Replace:
- `YOUR_TENANT_ID` with your Directory (tenant) ID
- `YOUR_CLIENT_ID` with your Application (client) ID

### Common tenant IDs

- **Specific tenant**: Use your tenant ID (e.g., `12345678-1234-1234-1234-123456789012`)
- **Organizations**: Use `organizations` (any Azure AD tenant)
- **Common**: Use `common` (any Azure AD or personal Microsoft account)

### Scopes

Default scopes work for most cases. Azure AD supports:
- `openid` (required)
- `profile` (user profile info)
- `email` (email address)
- `offline_access` (refresh tokens - automatically included by epithet)

---

## Generic OIDC provider

If your provider supports OIDC discovery (most modern providers do), you can use the generic configuration:

### Step 1: create OAuth2 application

Follow your provider's documentation to create an OAuth2 application with:
- **Application type**: Native, Desktop, or Public Client
- **Grant type**: Authorization Code
- **PKCE**: Enabled (required)
- **Redirect URI**: `http://localhost:8080/callback` (or wildcard if supported)

### Step 2: find OIDC discovery endpoint

Most providers expose OIDC discovery at:
```
https://your-provider.com/.well-known/openid-configuration
```

The issuer URL is usually the base URL (without `/.well-known/...`).

### Step 3: configure epithet

```bash
epithet agent \
  --ca-url https://ca.example.com \
  --auth "epithet auth oidc \
    --issuer https://your-provider.com \
    --client-id YOUR_CLIENT_ID \
    --scopes openid,profile,email"
```

---

## Testing your configuration

### Test the auth plugin directly

You can test authentication without running the full broker:

```bash
# Run the auth plugin manually
echo "" | epithet auth oidc \
  --issuer https://accounts.google.com \
  --client-id YOUR_CLIENT_ID \
  3>&1 1>/dev/null

# This should:
# 1. Open your browser
# 2. Prompt for authentication
# 3. Output state to fd 3 (which we redirect to stdout)
```

---

## Troubleshooting

### "Failed to create OIDC provider"

- Check that your `--issuer` URL is correct
- Verify your provider supports OIDC discovery
- Try accessing `{issuer}/.well-known/openid-configuration` in a browser

### "Authentication failed" in browser

- Verify your `--client-id` is correct
- Check that the OAuth app is enabled in your provider
- Ensure redirect URI is configured correctly (`http://localhost` or `http://localhost:8080/callback`)

### Browser opens but shows error

- **"redirect_uri_mismatch"**: Add `http://localhost:8080/callback` (or your configured port) to your OAuth app's redirect URIs
- **"invalid_client"**: Double-check your client ID
- **"unauthorized_client"**: Your OAuth app may not be configured for authorization code flow or PKCE

### Token refresh fails repeatedly

- Refresh token may have expired (Google: 6 months inactive)
- OAuth app may have been disabled or deleted
- User may have revoked access
- Solution: Delete broker state and re-authenticate (or restart broker)

### "This app isn't verified" (Google)

This is normal for personal OAuth apps. Options:
1. Click "Advanced" → "Go to {app name} (unsafe)" to proceed
2. Have your Google Workspace admin allowlist the app
3. Submit your app for Google verification (if you have many users)

## Next steps

- [Authentication overview](./authentication.md) - How auth plugins work
- [Example configurations](../examples/) - Complete working examples
