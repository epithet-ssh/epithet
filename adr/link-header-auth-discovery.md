# Link-header auth discovery

## Problem

`ca-url` is the only thing a client configures, but it is not sufficient to
find anything. The broker reaches the auth config by string-appending a path
it has compiled in:

```go
url := strings.TrimSuffix(caURL, "/") + "/discovery"   // pkg/caclient/caclient.go:263
```

That is a magic URL: the client and the server must independently agree on a
path that appears in neither the config nor the protocol. Changing where the
document lives means shipping new brokers.

The goal is that everything is reachable from `ca-url` alone, with no path
knowledge on either side.

## Decision

The CA advertises the location of its auth config with a **relative** `Link`
header on `GET <ca-url>`. The broker resolves that reference against the CA
URL it used and follows it.

```
GET / HTTP/1.1
Host: ca.internal:8443

HTTP/1.1 200 OK
Content-type: text/plain
Link: <discovery>; rel="https://epithet.dev/rel/auth"

ssh-ed25519 AAAAC3Nza...
```

The broker resolves `<discovery>` against `https://whee.example.com/epithet/ca/`
and fetches `https://whee.example.com/epithet/ca/discovery`.

`GET <ca-url>` is chosen as the entry point because it is literally the
configured value — no derivation at all — and it already exists as an
anonymous endpoint returning the CA public key.

## Why not RFC 9728

There is a real convention for this: RFC 9728 (OAuth 2.0 Protected Resource
Metadata, April 2025) has the protected resource answer a 401 with

```
WWW-Authenticate: Bearer resource_metadata="https://.../.well-known/oauth-protected-resource"
```

It was rejected for two independent reasons.

**The CA cannot know its own absolute URL.** RFC 9728 requires a `resource`
member (§2, REQUIRED) defined as "a URL that uses the https scheme and has no
fragment component" (§1.2), and the client MUST reject a document whose
`resource` does not match the URL it requested (§3.3). Behind a
prefix-stripping, TLS-terminating proxy a Go handler sees `r.URL.Path == "/"`,
a rewritten `Host`, and `r.TLS == nil`. Scheme, host, and path can all be
unknowable. Satisfying RFC 9728 therefore requires an operator-supplied
`--external-url`, i.e. exactly the deployment assumption this change exists to
remove.

**`WWW-Authenticate` has no relative-reference semantics.** RFC 9110 §11.6.1
defines auth-params as `token / quoted-string` with no URI resolution. RFC 8288
§3.1 by contrast: "If the URI-Reference is relative, parsers MUST resolve it as
per [RFC3986], Section 5." A relative pointer is only well-specified in `Link`.

Generic OAuth client interoperability — the one thing RFC 9728 would have
bought — is not a goal. `epithet agent` is the only client.

The mechanism works because resolution happens on the side that has the
information: the CA emits a string with no scheme, host, or prefix, and the
broker resolves it against a URL it knows absolutely because the operator
typed it in. The fact neither party holds alone is never needed by either.

## Design

### Relation type

```
https://epithet.dev/rel/auth
```

RFC 8288 requires extension relation types to be URIs. It carries no version
segment: the relation names the relationship ("the auth config for this CA"),
not the payload schema, so added fields in `wire.AuthConfig` do not change it.
The URI need not dereference, though pointing it at the discovery section of
`docs/authentication.md` is a free win if `epithet.dev` serves docs later.

### Server — `pkg/caserver/caserver.go`

`getPubKey` sets one header before `WriteHeader`:

```go
w.Header().Set("Link", `<discovery>; rel="https://epithet.dev/rel/auth"`)
```

Nothing else changes. `DiscoveryHandler`, its `Cache-Control` pass-through, and
the `/discovery` route in `cmd/epithet/ca.go:57` all stay exactly as they are.
The path stops being magic not because it moved, but because nothing
constructs it any more.

### Client — `pkg/caclient/caclient.go`

`doGetDiscovery(ctx, caURL)` becomes two requests:

1. `GET caURL` (as configured, verbatim — do not append a slash to the request
   itself; a proxy may be routing on the exact path).
2. Parse `Link` response headers. There may be several header lines, each with
   several comma-separated link-values. A single `rel` value is itself a
   space-separated list of relation types, so select the first link-value whose
   `rel` list *contains* the relation URI. Per RFC 8288 §3, `rel` may arrive as
   a token or a quoted-string; both MUST parse.
3. Resolve the target against the **resolution base** (below) using
   `net/url.URL.ResolveReference`.
4. Reject the result unless its scheme, host, and port match `caURL`'s.
5. `GET` the resolved URL and decode as today — same body-size limit, same
   `wire.Discovery` decode, same `CAUnavailableError` / `InvalidRequestError`
   status mapping.

### The resolution base — a trailing-slash rule

RFC 3986 §5 resolution is unforgiving here:

```
base https://whee.example.com/epithet/ca   + <discovery>  →  .../epithet/discovery    WRONG
base https://whee.example.com/epithet/ca/  + <discovery>  →  .../epithet/ca/discovery  right
```

**Rule: `ca-url` is treated as a collection base. If it has no trailing slash,
one is appended before resolution.** This is a deliberate deviation from using
the request URI as the base, and it is the single most likely thing to be
silently wrong, so it gets an explicit test with a slashless `ca-url`.

This imposes **no requirement on the user**, not even a soft one. The request
URL and the resolution base are separate values:

| | value |
|---|---|
| request URL | `ca-url` verbatim, as configured — never rewritten |
| resolution base | derived internally: scheme + host + path of the final URL, trailing slash forced |

`https://whee.example.com/epithet/ca` and `.../epithet/ca/` both work and
neither is "more correct." Do **not** normalize the configured value at load
time, reject a slashless `ca-url`, or log the normalized form — the verbatim
request path is what proxies route on, and the verbatim configured string is
what the operator has to match against their config when reading an error.

Base construction details: an empty path (`https://ca.example.com`) becomes
`/`; query and fragment are dropped from the base, since neither is meaningful
for a collection base and RFC 3986 §5 would discard the query anyway once the
reference has a non-empty path.

If the `GET` was redirected, the base is the **final** URL (`res.Request.URL`),
slash-normalized — not the configured `ca-url`. A proxy that 301s
`/epithet/ca` to `/epithet/ca/` would otherwise produce a resolution base that
does not match where the response actually came from. The same-origin check in
step 4 is still made against the configured `ca-url`, so a redirect cannot walk
the bootstrap off-origin.

Go has no `Link` parser in the standard library. Survey the existing Go
implementations before hand-rolling one; the parsing is small but the
token/quoted-string and space-separated-`rel` cases are exactly where a
hand-rolled version goes wrong.

### Interaction with failover

`doGetDiscovery` already receives the specific `caURL` that `breakerpool`
selected (`caclient.go:247`), so both requests and the resolution base all
refer to the same CA. Backup CAs mounted under different prefixes each
describe themselves correctly with no extra work. A failure on either request
propagates to the pool and trips that CA's breaker as before.

### Same-origin restriction

A `Link` target is a URI-Reference, so an absolute cross-host value is legal
per RFC 8288. We reject it. The CA is already trusted to choose the OIDC
issuer, so this is not a meaningful new trust boundary — it keeps TLS trust
anchored to the configured host and prevents a misconfiguration from silently
fetching bootstrap data off-origin. Loosen only if a real deployment needs it.

### Wire format

`wire.Discovery` and `wire.AuthConfig` are unchanged. No `resource`, no
`authorization_servers`, no RFC 9728 field names — nothing generic will ever
read this document.

## Version skew

**No fallback.** A broker that finds no matching `Link` on `GET <ca-url>`
fails with an error naming the CA URL and the expected relation, and saying
the CA is too old.

Old brokers keep working against new CAs for free, since `/discovery` stays
where it is. The reverse is not supported: a `/discovery` fallback would
re-bake the exact assumption being removed, and such fallbacks become
permanent. Single-operator deployment, and the OIDC stack is not merged, so a
clean break costs nothing.

## Testing

Unit — `pkg/caclient`:
- `rel` as bare token and as quoted-string
- several link-values in one header; several `Link` header lines
- no matching relation → version-skew error naming CA URL and relation
- unparseable `Link` → error
- resolution with and without a trailing slash on `ca-url` (the §5 gotcha)
- prefix-mounted CA that only ever sees `/` (via `http.StripPrefix`) resolves
  to the prefixed URL
- `rel` list containing several relation types, ours not first
- redirect from `/epithet/ca` to `/epithet/ca/` resolves against the final URL
- `ca-url` with empty path (`https://ca.example.com`) resolves correctly
- `ca-url` carrying a query string does not leak it into the resolved URL
- the configured `ca-url` string is unchanged after a discovery round trip
- absolute cross-origin `Link` target → rejected

Unit — `pkg/caserver`:
- `GET /` emits `Link` with the expected relation. This replaces the
  `require.Empty(t, resp.Header.Get("Link"))` assertion at
  `caserver_test.go:124`.
- `caserver_test.go:167` asserts the same on a **POST** response and stays as
  written — `Link` is added to `GET` only.

Integration:
- `test/server/server_test.go:119` currently `GET`s `/discovery` directly; add
  a case driving the full `GET <ca-url>` → `Link` → discovery path.
- Harnesses that mount handlers by hand (`test/sshd/broker_test.go:104`) must
  mount the root handler, not just `/discovery`, or no `Link` is emitted.

Run `go test -race ./pkg/caclient ./pkg/caserver` plus `make test`.

## Documentation

`docs/authentication.md` "## Discovery" documents `GET /discovery` as the
bootstrap endpoint. Rewrite to describe the `Link` hop, state the
trailing-slash rule, and show a prefix-mounted example.

## Rejected alternatives

### Content negotiation on `ca-url`

Serve both documents at `ca-url`, selected by `Accept`: `*/*` returns the
`text/plain` public key, a vendor media type returns the auth config, with
`Vary: Accept` on both. Attractive because it removes every line of URL
handling in this document and drops startup to a single request.

Rejected on the equivalence test. Fielding defines a resource as mapping to
entities "which are equivalent"; content negotiation selects among
representations conveying *the same information in different encodings*. The
public key and the auth config are disjoint — neither is derivable from the
other — so this is not negotiation, it is a switch statement wearing an
`Accept` header.

That abstract objection has a concrete failure mode. One cache key would hold
two unrelated documents with very different lifetimes: the public key is
effectively immutable, the auth config carries a proxied `max-age=300`. An
intermediary that mishandles `Vary` does not serve a *stale* answer, it serves
**the wrong document** — a public key where the broker expected auth config.
When representations really are equivalent, a `Vary` bug degrades gracefully;
when they are not, it produces nonsense.

The trade is also badly shaped. `Link` puts its complexity in one function in
one process, guarded by tests that pass or fail. Negotiation puts it in the
behavior of every cache and proxy between broker and CA — code we do not own,
cannot test, and will not see fail.

### Hinting available media types

Considered as a companion to negotiation: `Alternates` (RFC 2295, Transparent
Content Negotiation) is the purpose-built header — "the list of variants bound
to a negotiable resource" — but it is Experimental and effectively
unimplemented. `Link: <>; rel="alternate"; type="..."` works and is fully
standard (`<>` is a same-document reference, RFC 3986 §4.4). Both are moot
once negotiation is rejected: `alternate` is the wrong relation for a link to a
genuinely different resource.

## Out of scope

- `WWW-Authenticate` on 401s. Nearly free, but nothing consumes it: the broker
  discovers at startup, and the existing 401 path (`Auth.ForceRefresh`) is
  about token refresh, not re-discovery.
- `--external-url` config. It existed only to satisfy RFC 9728's `resource`.
- Removing `client_secret` from the bootstrap document (yatl task `hv`).
- The https-only constraint on the CA URL (yatl task `kw`).
