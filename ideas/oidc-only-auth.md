# OIDC-only authentication

**Date:** 2026-08-13
**Status:** Approved design, pending implementation plan

## Summary

Remove the pluggable subprocess authenticator system and standardize on OIDC with a
hard invariant: **the auth token is always a JWT, end to end**. Cascade the
simplifications that invariant unlocks — delete the base64 token wrapping, refresh
proactively from JWT `exp`, clamp cert TTL to token expiry, move host gating into
the user's ssh config and shrink discovery to an anonymous bootstrap endpoint, and
replace RFC 9421 service signing with CA-minted JWTs. SAML support, when it arrives, must terminate in a JWT (token exchange
or an OIDC-fronting IdP); it is purely a client-side acquisition concern and never
reopens the transport contract.

## Decisions

| Decision | Choice |
|---|---|
| Future SAML token shape | Always a JWT; the pipeline contract never changes |
| Replacement for subprocess plugins | Fully in-process OIDC, no public seam; extract an interface only when SAML lands |
| Proactive token refresh | In scope |
| Cert TTL clamp to token exp | In scope |
| Discovery | Single anonymous endpoint serving OIDC bootstrap config only; match patterns no longer exist to serve |
| CA↔policy service auth | Replace httpsig (RFC 9421) with short-lived CA-minted JWTs, in this effort |
| CA-side token validation | None; policy server is the sole validator (see §1) |
| Host gating | User ssh config via `Tag`/`Match tagged` (OpenSSH 9.4+); generated per-profile files keep the arcane exec; server-advertised match patterns removed |
| OIDC scopes | Not configurable; client hardcodes `openid profile email` |
| Config parsing rework | Separate change; direction recorded in §7 |
| Combined `epithet server` mode | Untouched. The CA/policy process boundary is deliberate; combined mode will likely be deleted in a separate change |

## 1. The token contract

One rule everywhere: the auth token is a JWT.

- Broker acquires it in-process, sends it verbatim as `Authorization: Bearer <jwt>`.
- CA passes it through untouched (no parsing, no validation).
- Policy server is the sole validator: JWKS signature, issuer, audience, expiry.

**Why the CA does not validate.** CA-side validation would be additive machinery,
not a replacement: the policy server must validate regardless, since it is the
decision point and cannot take identity on faith from an upstream header. It would
also give the CA an outbound IdP/JWKS dependency (new egress and failure mode for
the internet-facing component) and create two validators whose behavior — audience,
clock skew, accepted algorithms — must be kept identical to avoid "CA accepts,
policy rejects" states. The bootstrap flow does not need it either: discovery is
anonymous (§4), so no token ever appears on that path. Revisit only if shielding
the policy server from junk-token load ever matters, and prefer rate limiting at
the CA for that.

Delete the base64url encode (`pkg/broker/auth.go:325`) and decode
(`pkg/policyserver/policyserver.go:210`), the "Invalid token encoding" error branch,
and the binary-preservation test. JWTs are already base64url-segmented ASCII; the
wrapping existed only because plugins could emit arbitrary bytes.

## 2. Broker: in-process OIDC

Rewrite `pkg/broker/auth.go` from a subprocess harness (~378 lines) to a thin wrapper
calling `pkg/auth/oidc` as a library.

- Refactor `pkg/auth/oidc`: `Run` returns `(idToken string, state oauth2.Token)` and
  takes an `io.Writer` for user-facing messages ("visit this URL…"), instead of
  writing token to stdout and state to fd3.
- User messages flow into the existing gRPC `MatchEvent.user_output` stream unchanged.
- Delete outright: `sh -c` execution, the fd3/fd4 pipe protocol, `MaxStateBlobSize`,
  process-group kill + `commandWaitDelay`, mustache templating (drop the
  `cbroglie/mustache` dependency if nothing else uses it), and the ~100-line
  singleflight replay machinery. Concurrent ssh sessions share a mutex-guarded token
  source; joiners see the same in-process writer.
- Refresh state (`oauth2.Token`) stays in memory only, as today.

**One pragmatic seam, tests only:** `broker.New` takes the token-acquisition function
as a constructor argument — a plain `func(ctx context.Context, out io.Writer) (string, error)`,
not an exported interface. `cmd/epithet` wires the OIDC implementation; tests inject
a fake that mints signed JWTs. Nothing in config, discovery, or docs exposes this.

Security payoff: closes the `sh -c` on CA-controlled discovery string RCE
(`.tasks/open/t761tcz9.md`) by removing the vector; moots `mrrf0wa8` (connection
details in mustache templates) and `6jm8vvtv` (SSH-session env var for plugins).

## 3. Proactive token refresh

The broker parses `exp` from the JWT — an unverified local parse; it is advisory
only, the policy server still does real verification — and refreshes ahead of expiry
using the same `expiryBuffer` idiom the cert store uses.

- The reactive `401 → ClearToken → re-auth → retry` loop in the cert path
  (`pkg/broker/broker.go:274-360`) collapses to: proactive refresh, plus a
  **single** forced-refresh retry on 401 as a safety net for revocation and clock
  skew. `maxRetries` goes away. Its twin in the discovery path (`:499-544`) is
  deleted outright with §4.
- The five terminal `errors.As` branches in the cert-request loop collapse; they all
  produce the same `MatchResponse{Allow: false, Error: err.Error()}` shape.

## 4. Host gating moves to ssh config; discovery shrinks to bootstrap

Server-advertised host match patterns are removed entirely. Which hosts epithet
handles is decided by the **user's own ssh config** — the place ssh already decides
everything else — using `Tag` / `Match tagged` (OpenSSH 9.4+), the mechanism that
exists for exactly this: conditionally applying configuration that lives in
included files.

The reason gating originally drifted server-side is that the glob-included file
opens with a top-level `Match exec`, and a `Match`/`Host` line inside an included
file terminates any enclosing block, so users could not scope our `Include` under
their own `Host` patterns — and hand-writing the `Match exec` invocation themselves
would be fat-finger-prone and would freeze an interface we want to keep evolving.
Tags solve both: users write one arcana-free keyword; every arcane invocation stays
inside the generated, epithet-owned file.

    # ~/.ssh/config — user-owned, zero arcana
    Host *.home
        Tag epithet-home
    Host *.work
        Tag epithet-work
    Include ~/.epithet/run/*/ssh-config.conf   # at the end: tags must be set first

    # generated ~/.epithet/run/home/ssh-config.conf — epithet-owned,
    # regenerated every agent start
    Match tagged epithet-home exec "<epithet> match --host '%h' ... --broker '<sock>'"
        IdentityAgent ~/.epithet/run/home/%C

Pieces of the design:

- **Named profiles.** Agents get a `name` ("home", "work"); the rundir becomes
  `~/.epithet/run/<name>/` and the tag `epithet-<name>`, replacing the opaque
  CA-URL hash. Multi-CA is N named agents, each generated file gated by its own
  tag — the user's tags take over disambiguation from today's per-CA `Match exec`
  race, and the paste-once glob `Include` keeps working for any number of agents.
- **Invocation control is preserved.** The `Match tagged … exec` line is
  regenerated on every agent start, so the exec contract can evolve freely across
  epithet versions; users never type, paste, or update it.
- **Ordering matters.** `Match tagged` is evaluated against tags already set at
  parse time, so the `Include` must come after the `Host`/`Tag` blocks. The
  agent's existing ssh-config check (`checkSSHConfigInclude`) additionally warns
  when the Include precedes any `Tag` line.
- **Version floor.** `Tag`/`Match tagged` requires OpenSSH 9.4 (2023); document
  it. macOS Sequoia and Ubuntu 24.04 qualify.

Explicit user scoping keeps epithet out of unrelated ssh traffic and keeps non-org
hostnames from ever reaching the org's CA. When `epithet match` reaches the broker,
the broker handles the host, period: `shouldHandle`, the pattern cache, the
per-match discovery lookup, and the client-side copy of the glob matcher
(`pkg/policy/policy.go:34-46`) are all deleted. Failure semantics are unchanged:
tag unmatched or broker down → block skipped / exec fails → normal key/password
fallback.

**The policy server loses its matching contract.** Host-pattern matching was part
of the policy server's public API: advertised patterns had to mean the same thing
to the broker's matcher as to the evaluator, which is why the glob logic existed in
two implementations that had to stay semantically in sync. Now matching is entirely
private to the policy server — it receives `(identity, host, user)` and makes a
decision; how it decides is unobservable from outside the process. Third-party
policy servers lose a whole contract surface, and the evaluator refactors in §5
carry zero compatibility concerns. No parameters of the decision ever leave the
decision-maker.

What this buys:

- The authenticated discovery tier disappears, and with it the pattern-leak
  concern, token forwarding on the discovery path, and the tiering logic.
- ssh connections to non-epithet hosts no longer invoke epithet at all.
- A CA outage can no longer break host matching (today a failed discovery lookup
  silently returns "not handled" with an empty error).
- The dynamic-policy discovery staleness bug becomes moot. The policy `Hosts` map
  keeps doing its real job — authorization and TTL selection at cert-request time —
  and an out-of-policy host in a user's ssh config just gets a policy denial with a
  real error message.

What is given up: central propagation of pattern changes to clients. Acceptable —
patterns change rarely, orgs already distribute the CA URL, and today's propagation
is broken anyway (patterns are snapshotted at policy-server startup, so dynamic
updates never reached clients).

Discovery survives as a single anonymous endpoint, `GET /discovery`, returning only
the OIDC bootstrap config (`issuer`, `client_id`) — how a fresh client learns to
authenticate, mirroring OIDC's own public `/.well-known/openid-configuration`. The
CA passes it through from the policy server; the broker fetches it once at agent
startup. Deleted along the way:

- The empty-connection `RequestPolicy` probe (`pkg/caserver/caserver.go:99-137`),
  the CA-side `httpcache` discovery cache, and the CA-side tiering.
- `Hello`/`doHello`/`handleHello` and the pointer-field request-shape routing in
  `CreateCertRequest`.
- Link-header learning and the hand-rolled `parseLinkHeader`; the discovery URL is
  `caURL + "/discovery"`.
- The `gregjones/httpcache` dependency and caclient's second HTTP client — fixing
  two bugs by removal: the discovery client silently ignored
  `--insecure`/`--tls-ca-cert`, and it bypassed the breakerpool so a CA outage
  became a silent match failure with an empty error.
- `MatchPatterns` from the discovery response and wire types, and
  `HostPatterns()` from the policy server.

## 5. Policy server and CA

- Delete the `TokenValidator` interface; handlers take the concrete
  `*oidc.Validator` (constructors already return it). Take `ctx` in
  `ValidateAndExtractIdentity` so JWKS fetches respect request timeouts.
- `client_id` becomes **required** OIDC config, so audience checking can never be
  silently skipped (resolves `.tasks/open/1g8ka9wq.md`).
- Delete dead code: `oidc.Validator.ValidateAccessToken`, `ca.AuthToken`,
  `oidc.Config.SkipExpiryCheck`, and the server-side inventory below.
- The CA stays a dumb pass-through; all trust decisions live in the policy server.

**Cert TTL clamp.** Validation returns claims (identity + `ExpiresAt`) instead of a
bare identity string. The clamp travels as an absolute `NotAfter time.Time` in
`CertParams` — a relative duration would decay between evaluation and signing —
and `SignPublicKey` uses `min(now + expiration, NotAfter)`. Certificates never
outlive the auth session.

**Clamp prerequisite (correctness):** host-policy expiration lookup currently
iterates a Go map with `break // first match` (`evaluator.go:131-145`), so
overlapping patterns yield a randomly chosen TTL per request. Pattern matching
becomes deterministic (ordered, most-specific-first or config order) before TTL
gains security semantics. While there: collapse the three separate walks of `Hosts`
per request into one pass, and merge the structurally identical `DefaultPolicy` /
`HostPolicy` into a single `Rules` type.

## 6. CA↔policy service auth: JWT instead of RFC 9421

Replace `pkg/httpsig` (246 lines plus the `yaronf/httpsign`/`httpsfv` dependency
tree) with a short-lived CA-minted JWT on every CA→policy request:

- `Authorization: Bearer <jwt>`, signed with the CA's key.
- Claims: `iss` (CA identity), `aud: "policy"`, `iat`, `exp` (~60 s), `jti`, and a
  body-hash claim `bh = base64url(sha256(body))` for request integrity.
- Policy server verifies against the already-configured `ca_pubkey`, checks
  freshness, recomputes the body hash.
- Verification becomes **required**: delete the nil-verifier-when-no-pubkey branch
  (nothing in `cmd/` could produce it), and `NewHandler` returns an error on a
  malformed key instead of panicking.
- SSH-key-type → JWS-alg mapping (ed25519→EdDSA, RSA→PS256, ECDSA→ES256/ES384) is
  the one small switch that survives from httpsig.

Result: exactly one authentication concept in the system — bearer JWTs, verified at
the policy server. User tokens verify against the IdP's JWKS; service tokens verify
against the CA's public key.

This is a protocol change for third-party policy servers;
`docs/policy-server-api.yaml` is updated to match (it currently documents an API the
code no longer implements in several ways — see §9).

## 7. Configuration

`BootstrapAuth` loses `Type`, `Command`, and `Scopes`, becoming
`{issuer, client_id, client_secret?}`. Scopes stop being configuration entirely:
nothing in epithet consumes any claim beyond `email`/`sub`, so the client hardcodes
`openid profile email` — today's default for the already-optional `scopes` config
that nothing needs to override. Delete `OIDCConfig.Scopes`, `DefaultScopes`, and the
`--scopes` plumbing; trivially reversible if an IdP ever requires an extra scope.
Delete `AuthConfigToCommand` and its
switch, the `os.Executable()` self-re-exec trick, and the `"epithet"` substring
substitution. The agent's `--auth` flag and `agent.auth` config key are removed —
discovery is the path.

**Wire-type consolidation:** one shared package, `pkg/wire`, holds `CertParams`, the policy request/response, discovery response,
auth config, and error types. Today `BootstrapAuth` exists ×3, the
policy/discovery/error responses ×2–3, the CA builds the policy request as an
untyped map while the server decodes a typed struct, and `pkg/policyserver` imports
`pkg/ca` just for `CertParams` (dragging the CA client into the policy binary).

**Config parsing rework: separate change.** The policy server's config parsing is
jank, and policy *rules* deserve to be treated as a separate document from server
config — but that rework ships as its own change, not this one. Direction, recorded
here as the seed for that change: kong (CLI + kongyaml) owns all scalars, and
`config.LoadSection` decodes only the rules maps (`Users`, `Defaults`, `Hosts`)
into `PolicyConfig`. That change deletes `PolicyRulesConfig` and its
`Validate`/`BootstrapAuth`/`ExtractServerConfig`, the manual CLI-over-config
re-apply block (`policy.go:180-191`), the snake_case/kebab-case dual spelling, the
per-request `ParseDuration` fallthrough in `getExpiration` (parse once at load into
`time.Duration`), the dead `ServerConfig.PolicyURL` field, the silently-ignored
`--default-expiration` flag, and `resolveCAPubkey`'s prefix-sniffing key validation
(use `ssh.ParseAuthorizedKey`).

Still in this effort, because it is entangled with the JWT work:

- Raise the three disagreeing 8 KiB body limits (`caserver.go:182`, policyserver
  `MaxRequestSize`, and the `io.LimitReader`-then-parse response reads in
  `ca.go:237,298`). Real ID tokens with group claims run 4–8 KiB; truncation must
  report "too large", not "unexpected end of JSON input".

## 8. Wire compatibility

No proto changes. `MatchEvent.user_output` keeps its field; its meaning narrows from
"arbitrary plugin fd4 bytes" to "broker auth progress messages". Comment updates
only — no regeneration, no gRPC compatibility concerns.

## 9. Docs

- Rewrite `docs/authentication.md` as an OIDC document; the plugin protocol spec,
  bash/python plugin examples, `examples/bash_auth_example.bash`, and the osascript
  example plugin all go.
- README, `docs/architecture.md`, `docs/oidc-setup.md`, `docs/policy-server.md`
  drop "any auth plugin / could be a SAML assertion" language for the JWT contract.
- `docs/policy-server-api.yaml` gets a full correctness pass: `expiration` is
  documented as a duration string but marshals as integer nanoseconds (moot once
  `NotAfter` lands), `policy.hostPattern` is now `policy.hostUsers`, auth is
  documented as `X-CA-Signature` but becomes the bearer JWT of §6, the example
  token needs no base64 wrap once §1 lands, and `GET /discovery` is undocumented.

## 10. Testing strategy

A shared **fake IdP test helper** (OIDC discovery endpoint + JWKS + mints real
signed JWTs + auto-approving authorization endpoint) replaces all shell-script fake
plugins. This upgrades three suites at once:

- `test/policy` can finally exercise the real validation path (its comments
  currently note it cannot, absent a live OIDC provider).
- `test/server` drops its hand-rolled mock IdP.
- `test/sshd` exercises the genuine flow non-interactively: the harness reads the
  auth URL from user output, follows it, the fake IdP auto-redirects to the local
  callback, and the real OIDC code path completes.

Broker unit tests use the injected token function. The ~700 lines of shell-script
test scaffolding in `pkg/broker/auth_test.go`, `auth_singleflight_test.go`, and the
integration tests become in-process fakes. New coverage needed: proactive refresh
timing, TTL clamp (including `NotAfter` in the past → reject), anonymous discovery,
tag-gated ssh config (the sshd integration test drives a real `Tag`/`Match tagged`
config end to end, including a non-tagged host that must bypass epithet), and
service-JWT verification (expired, wrong `aud`, body-hash mismatch, wrong key).

## Dead code inventory (delete in this effort)

Client side: `Broker.BrokerSocketPath`, `Broker.LookupCertificate`,
`Broker.StoreCertificate`, `Broker.Match` + `MatchRequest`/`MatchResponse`
(net/rpc-shaped leftover), `BrokerServer.agentSocketPathForHash`,
`agent.IsAgentStopped`, the unused keypair and `caClient` field in `pkg/agent`,
`caclient.WithHTTPClient`, `caclient.SetDiscoveryURL`, breakerpool test-only
exports, the `var _ *ssh.Certificate` no-op in `inspect.go`, the stale
`~/.epithet/broker.sock` default on `epithet match`.

Server side: `ca.AuthToken`, `ca.WithHTTPClient`, `caServer.httpClient`,
`Evaluator.validator` field, `ValidateAccessToken`,
`ErrUnauthorized`/`ErrForbidden`/
`ErrNotHandled`, `MultiCertLogger`, `certEventForJSON`/`CertEvent.toJSON` (comment
references an `S3CertArchiver` that does not exist), `httpsig.Signer.KeyID`,
unused `oidc.Claims` fields (keep `Identity`, `ExpiresAt`),
`pkg/policyserver/discovery.go` (tombstone file), `TestURLStuff` (tests the stdlib).

Also: extract the 19 copies of the caserver error-response boilerplate into one
helper, with `setDiscoveryLink` as middleware (it is currently forgotten on two
paths).

## Explicitly out of scope (file as yatl tasks)

- Combined `epithet server` rework or deletion — separate change, user decision
  pending.
- Policy server config parsing rework — separate change; direction recorded in §7.
- Agent socket `Listen()`/`Serve()` split (socket may not exist when `Match`
  returns allow; listener failure only logged).
- Unified cert/token expiry tracking (two parallel expiry state machines; cert
  expiry parsed three times per match).
- `Broker.Inspect` holds the broker lock across a network call and uses
  `context.Background()`.
- Inspect triple-representation collapse (Go structs / proto / CLI JSON with two
  hand-written converters).
- `sshcert.Parse` wraps a nil error; caserver re-implements `sshcert.Parse` and
  fingerprinting.
- `tlsconfig.ValidateURL` case-sensitive scheme check.
- Match gRPC `MatchResult.error` vs exit-code redundancy; log-only `Connection`
  fields (`local_host`, `port`, `proxy_jump`).

## Open yatl tasks this effort resolves

- `t761tcz9` — `sh -c` on CA-controlled discovery string (RCE): vector removed.
- `1g8ka9wq` — audience check silently skipped when `client_id` empty: now required.
- `mrrf0wa8` — connection details in mustache templates: templating removed.
- `6jm8vvtv` — SSH-session detection env var for plugins: plugins removed.
