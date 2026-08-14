# Authentication

Epithet authenticates with OIDC only. There is no plugin protocol and no
subprocess auth command: the broker (`epithet agent`) authenticates
in-process using `pkg/auth/oidc`, and the resulting token is a JWT from
first acquisition to final verification.

## The token contract

One rule holds everywhere: the auth token is always a JWT.

- The broker acquires it in-process via the OIDC authorization-code-with-PKCE
  flow and sends it verbatim as `Authorization: Bearer <jwt>` when it
  requests a certificate.
- The CA passes it through untouched — no parsing, no validation. All trust
  decisions live in the policy server.
- The policy server is the sole validator: it checks the JWT's signature
  against the issuer's JWKS, its issuer, its audience (`client_id`, which is
  required configuration), and its expiry.

Because the token is always a JWT, there is no wrapping or encoding step
between acquisition and use — a JWT is already base64url-segmented ASCII.

## Discovery

Before the broker can authenticate anyone, it needs to know which OIDC
issuer and client ID to use. It fetches this once at startup from the CA's
anonymous bootstrap endpoint:

```
GET /discovery
```

```json
{
  "auth": {
    "issuer": "https://accounts.google.com",
    "client_id": "123456.apps.googleusercontent.com"
  }
}
```

This endpoint requires no token — a fresh client has none yet — and the CA
serves it as a pass-through of the policy server's own `GET /` discovery
response. There are no server-advertised host-match patterns in this
document; which hosts epithet handles is decided entirely by the user's own
ssh config (see [architecture.md](architecture.md)).

## In-process OIDC flow

`epithet agent` calls `pkg/auth/oidc.Authenticate(ctx, cfg, prev, out)`,
which drives an authorization-code flow with PKCE:

1. Opens the user's browser to the identity provider's authorization
   endpoint (or prints the URL to `out` if it can't launch a browser).
2. Runs a local callback listener to receive the authorization code.
3. Exchanges the code for tokens and returns the ID token (a JWT).

Scopes are not configurable: the client always requests
`openid profile email`. This is the only claim set anything in epithet
consumes (`email`/`sub` for identity), so there is nothing to override.

On later calls, `prev` carries the previous `oauth2.Token` (including its
refresh token). `Authenticate` reuses a still-valid access token or uses the
refresh token to get a new one silently, without opening a browser.

## Refresh state

Refresh state (an `oauth2.Token`) lives in memory only, inside the broker
process. It is never written to disk and never persisted across broker
restarts. Concurrent ssh sessions share one token source
(`pkg/broker.Auth`): the first caller to need a token runs the fetch, and
concurrent joiners are coalesced onto that same in-flight attempt, seeing a
replay of its user-visible output (e.g. "visit this URL...") rather than
triggering a second browser flow.

## Proactive refresh

The broker parses the `exp` claim out of its cached JWT — an unverified
local read, advisory only; the policy server still does the real
verification — and refreshes ahead of expiry once fewer than `expiryBuffer`
remains, the same idiom the rest of epithet uses for expiry buffers. Most
certificate requests never wait on an auth round trip because the token is
already fresh.

## The 401 safety net

Proactive refresh handles the common case, but a token can still be rejected
— server-side revocation, clock skew, or an IdP-side session change. If the
CA returns 401 for a certificate request, the broker calls
`Auth.ForceRefresh`, which discards the cached token, forces a genuinely new
token (not a replay of the one just rejected), and retries the certificate
request exactly once. There is no unbounded retry loop and no
`maxRetries` counter — one forced refresh is the entire safety net.

## Troubleshooting

**Browser doesn't open / "visit this URL" printed instead**

Normal in headless or remote-shell environments — copy the printed URL into
any browser with access to your identity provider.

**Repeated re-authentication**

The refresh token may have expired or been revoked, or the OAuth
application may have been disabled. Since refresh state is memory-only,
restarting `epithet agent` also forces full re-authentication.

**"Invalid token" from the CA / connection refused**

The policy server rejected the JWT — check its logs. Common causes: issuer
mismatch, expired token, or `client_id` not matching the token's audience.

See the [OIDC setup guide](oidc-setup.md) for provider-specific
configuration and the [policy server guide](policy-server.md) for how
tokens are verified.
