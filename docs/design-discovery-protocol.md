# Design: Discovery protocol and CA-to-policy authentication

## Context

The discovery bootstrap protocol lets agents learn auth config and host patterns from the CA without pre-configuration. The current implementation relays discovery URLs via Link headers from policy server → CA → client, but this breaks behind reverse proxies (combined mode rewrites the policy URL to `http://localhost`). The CA also lacks proper authentication to the policy server for non-cert requests.

## Design

### Client-facing API (CA serves these)

**`GET /`** — CA public key
- Returns: public key as plain text
- Headers: `Link: </discovery>; rel="discovery"`
- No auth required

**`GET /discovery`** — auth params + host patterns (no auth required)
- Returns JSON: `{"auth": {"type": "oidc", "issuer": "...", "client_id": "...", "client_secret": "...", "scopes": [...]}, "matchPatterns": ["*.example.com", ...]}`
- No auth/unauth split — patterns are for SSH `match` routing, not access control. Policy server makes access decisions per-request.
- `client_secret` is included — Google's OIDC flow requires it and it's not actually confidential (native/installed app flow).
- Cache headers from policy server passed through

**`POST /`** — cert request (unchanged from today)

### CA-to-policy server communication

**`GET /`** on policy server — returns auth params + host patterns as JSON
- CA signs the request using RFC 9421 (HTTP Message Signatures) with its ed25519 private key
- Policy server verifies using the CA's public key (already has via `--ca-pubkey`)
- Policy server returns appropriate `Cache-Control` headers
- CA uses `gregjones/httpcache` (already a project dependency) for HTTP caching — fetches on every client request, cache transport handles freshness per `Cache-Control` headers

**`POST /`** on policy server — cert evaluation (existing flow)
- Moves from current "sign body, put in Bearer header" to RFC 9421 signing
- Signs: `@method`, `@path`, `@authority`, `content-digest`, `created`
- Policy server verifies signature before evaluating

### RFC 9421 signing details

- **Library**: `yaronf/httpsign` (Apache 2.0, actively maintained, RFC test vectors, ed25519 support)
- **Algorithm**: ed25519 using the CA's existing SSH private key (same raw key material as `crypto/ed25519`)
- **Covered components for GET**: `@method`, `@path`, `@authority`; params: `created`, `expires`, `keyid`
- **Covered components for POST**: `@method`, `@path`, `@authority`, `content-digest`; params: `created`, `expires`, `keyid`
- **Replay protection**: `created` + `expires` (short window, e.g. 30s). Policy server rejects signatures outside the window.
- **`keyid`**: CA public key fingerprint (policy server resolves via its configured `--ca-pubkey`)
- **Verification**: policy server uses `yaronf/httpsign` verification middleware, looks up key by `keyid` against configured CA pubkey

### Policy server `GET /` response

```json
{
  "auth": {
    "type": "oidc",
    "issuer": "https://accounts.google.com",
    "client_id": "...",
    "client_secret": "...",
    "scopes": ["openid", "profile", "email"]
  },
  "matchPatterns": ["*.example.com", "*.prod.internal"],
  "defaultExpiration": "5m"
}
```

Headers: `Cache-Control: max-age=300`

### Combined mode (`epithet server`) simplification

Current: reverse proxy mux routes `/discovery` → policy, `/*` → CA.

New: just start policy subprocess and CA subprocess pointed at it. CA handles everything. No mux needed — CA listens on the public port directly (or a dumb TCP proxy forwards to it).

```
epithet server
  └─ starts: epithet policy --listen unix:///tmp/.../policy.sock
  └─ starts: epithet ca --policy unix:///tmp/.../policy.sock --listen :8080
```

### What changes, what stays

**Changes:**
- CA serves `/discovery` (new handler, fetches from policy server)
- CA always sets `Link: </discovery>; rel="discovery"` on all responses (hardcoded, it's the CA's own endpoint)
- CA→policy auth moves to RFC 9421 (replaces current body-sign + Bearer approach)
- Policy server `GET /` returns discovery data as JSON
- Policy server verifies RFC 9421 signatures on all requests
- `epithet server` drops reverse proxy mux
- Remove `extractLinkURLs` from CA and discovery URL relay/caching logic

**Stays:**
- `GET /` on CA returns public key as plain text
- `POST /` on CA for cert requests (just signing method changes)
- Client `parseLinkHeader` with relative URL resolution (already implemented)
- Policy server evaluates cert requests (CA doesn't make policy decisions)
- `--ca-pubkey` on policy server for key verification

### Migration path

The current Bearer-signature approach on cert requests should be replaced by RFC 9421 signing. This is a breaking change between CA and policy server (they must be upgraded together). Client protocol is backwards compatible — clients already follow Link headers.

## Files to modify

- `pkg/caserver/caserver.go` — add `/discovery` handler, hardcode Link header
- `pkg/ca/ca.go` — add `FetchDiscovery()` method (HTTP GET to policy), remove discovery URL relay logic, add RFC 9421 signing to all policy requests
- `pkg/policyserver/policyserver.go` — add `GET /` handler returning discovery JSON, add RFC 9421 verification middleware
- `cmd/epithet/server.go` — simplify: remove reverse proxy mux, just start CA on public port
- `cmd/epithet/ca.go` — wire up new discovery handler
- `go.mod` — add `yaronf/httpsign` dependency

## Verification

1. `go test ./...`
2. Test against epithet.brianm.dev:
   - `curl https://epithet.brianm.dev/` → public key + Link header
   - `curl https://epithet.brianm.dev/discovery` → auth params JSON
   - `./epithet agent --ca-url https://epithet.brianm.dev` → discovers auth, starts broker
