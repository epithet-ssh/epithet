# OIDC-only authentication implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** `ideas/oidc-only-auth.md` — read it before starting any task.

**Goal:** Remove the pluggable subprocess authenticator system; the auth token is a
JWT end to end, acquired in-process via OIDC, with the cascade of simplifications
that unlocks.

**Architecture:** The broker acquires ID tokens in-process (`pkg/auth/oidc` as a
library, injected as a `TokenFunc`), sends them bare as `Authorization: Bearer`,
the CA passes them through, and the policy server is the sole validator. Host
gating moves into the user's ssh config via `Tag`/`Match tagged`; discovery shrinks
to an anonymous OIDC-bootstrap endpoint; CA→policy service auth becomes a
CA-minted JWT; wire types consolidate into `pkg/wire`.

**Tech Stack:** Go 1.25, `coreos/go-oidc/v3`, `golang.org/x/oauth2`,
`go-jose/go-jose/v4` (JWT mint/verify — already in the module graph via go-oidc),
kong CLI, jj for VCS. gRPC/protobuf are **removed** in Task 12b (broker IPC
becomes newline-framed JSON over the unix socket).

## Global constraints

- **No commits by the executor.** Brian drives all `jj` operations. Each task ends
  with a **Checkpoint** step: run the verification commands, report results, stop.
  If executing task-by-task with review gates, the reviewer (Brian) describes the
  change with a Conventional Commit message (`feat:`/`fix:`/`chore:`/`docs:`) and
  runs `jj new` between tasks.
- Version control is **jj**, not git. Never run `git commit`.
- Build/test: `make build`, `make test`. Broker concurrency changes: also
  `go test -race ./pkg/broker`.
- Never edit generated files in `pkg/brokerv1` while they exist; Task 12b
  deletes `proto/`, `pkg/brokerv1`, and the buf toolchain entirely.
- OpenSSH **9.4+** is the floor for the generated ssh config (`Tag`/`Match tagged`).
- OIDC scopes are **not configurable**: the fixed list is `openid profile email`.
- Docs style: sentence-case headings; periods at the end of code comments;
  comments explain "why", not "what".
- Task tracking outside this plan file uses `yatl` (see Task 16), never TodoWrite.
- Integration tests live at `test/<name>/<name>_test.go`; temp dirs holding Unix
  sockets use `os.MkdirTemp("/tmp", "xx")` (macOS 104-byte socket path limit);
  test binaries build with `go build -o <tmpdir>/epithet ../../cmd/epithet`.

---

### Task 1: Fake IdP test helper (`pkg/oidctest`)

Everything downstream tests against real signed JWTs. This helper is a tiny OIDC
provider on `httptest.Server`: discovery doc, JWKS, auto-approving authorize
endpoint, token endpoint, and a `MintIDToken` helper for direct-injection tests.

**Files:**
- Create: `pkg/oidctest/oidctest.go`
- Test: `pkg/oidctest/oidctest_test.go`

**Interfaces:**
- Consumes: nothing from this plan.
- Produces (used by Tasks 4, 10, 14):
  - `func New(t *testing.T) *IdP` — starts the server, registers cleanup.
  - `func (p *IdP) Issuer() string` — base URL (also the `iss` claim).
  - `const ClientID = "epithet-test-client"` — the `aud` all minted tokens carry.
  - `func (p *IdP) MintIDToken(email string, expiresAt time.Time) string` — signed RS256 JWT with `iss`, `aud: ClientID`, `sub: email`, `email`, `iat`, `exp`.
  - `func (p *IdP) MintIDTokenWithAudience(email string, aud string, expiresAt time.Time) string` — for wrong-audience tests.
  - The `/auth` endpoint immediately 302s to `redirect_uri?code=<fixed>&state=<echoed>`; `/token` returns a JSON token response whose `id_token` is minted for `TokenEmail` (`const TokenEmail = "test@example.com"`) expiring in 5 minutes — this is what lets the real browser-flow code path complete non-interactively.

- [ ] **Step 1: Write the failing test**

```go
// pkg/oidctest/oidctest_test.go
package oidctest

import (
	"context"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
)

func TestMintedTokenVerifiesAgainstJWKS(t *testing.T) {
	idp := New(t)

	provider, err := gooidc.NewProvider(context.Background(), idp.Issuer())
	require.NoError(t, err)

	verifier := provider.Verifier(&gooidc.Config{ClientID: ClientID})
	tok := idp.MintIDToken("alice@example.com", time.Now().Add(5*time.Minute))

	idToken, err := verifier.Verify(context.Background(), tok)
	require.NoError(t, err)

	var claims struct {
		Email string `json:"email"`
	}
	require.NoError(t, idToken.Claims(&claims))
	require.Equal(t, "alice@example.com", claims.Email)
}

func TestExpiredTokenFailsVerification(t *testing.T) {
	idp := New(t)
	provider, err := gooidc.NewProvider(context.Background(), idp.Issuer())
	require.NoError(t, err)
	verifier := provider.Verifier(&gooidc.Config{ClientID: ClientID})

	tok := idp.MintIDToken("alice@example.com", time.Now().Add(-1*time.Minute))
	_, err = verifier.Verify(context.Background(), tok)
	require.Error(t, err)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/oidctest -run TestMinted -v`
Expected: FAIL — package does not exist / `New` undefined.

- [ ] **Step 3: Implement the fake IdP**

```go
// pkg/oidctest/oidctest.go
// Package oidctest provides a minimal in-process OIDC provider for tests.
// It serves a discovery document, JWKS, an auto-approving authorization
// endpoint, and a token endpoint, and can mint signed ID tokens directly.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ClientID is the audience carried by every minted token.
const ClientID = "epithet-test-client"

// TokenEmail is the identity minted by the /token endpoint (browser-flow path).
const TokenEmail = "test@example.com"

type IdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
}

func New(t *testing.T) *IdP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	p := &IdP{key: key, signer: signer}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/keys", p.handleJWKS)
	mux.HandleFunc("/auth", p.handleAuth)
	mux.HandleFunc("/token", p.handleToken)

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *IdP) Issuer() string { return p.server.URL }

func (p *IdP) MintIDToken(email string, expiresAt time.Time) string {
	return p.MintIDTokenWithAudience(email, ClientID, expiresAt)
}

func (p *IdP) MintIDTokenWithAudience(email, aud string, expiresAt time.Time) string {
	claims := map[string]any{
		"iss":   p.server.URL,
		"aud":   aud,
		"sub":   email,
		"email": email,
		"iat":   time.Now().Unix(),
		"exp":   expiresAt.Unix(),
	}
	raw, err := jwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		panic(fmt.Sprintf("oidctest: mint token: %v", err))
	}
	return raw
}

func (p *IdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.server.URL,
		"authorization_endpoint":                p.server.URL + "/auth",
		"token_endpoint":                        p.server.URL + "/token",
		"jwks_uri":                              p.server.URL + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *IdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: p.key.Public(), KeyID: "test-key", Algorithm: "RS256", Use: "sig",
	}}}
	writeJSON(w, jwks)
}

// handleAuth auto-approves: it redirects straight back to the client's
// redirect_uri with a fixed code, echoing state. This is what makes the real
// authorization-code flow completable without a browser or a human.
func (p *IdP) handleAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect+"?code=test-code&state="+q.Get("state"), http.StatusFound)
}

func (p *IdP) handleToken(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"access_token":  "test-access-token",
		"token_type":    "Bearer",
		"refresh_token": "test-refresh-token",
		"expires_in":    300,
		"id_token":      p.MintIDToken(TokenEmail, time.Now().Add(5*time.Minute)),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
```

Note: `go-jose/v4` is currently an indirect dependency; `go mod tidy` promotes it
to direct. Do not add any other new dependency.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go mod tidy && go test ./pkg/oidctest -v`
Expected: PASS (both tests).

- [ ] **Step 5: Checkpoint**

Run: `make build && make test`. Report results; stop for review.

---

### Task 2: `pkg/wire` — consolidate the wire types

One package holds every type that crosses a process boundary. This task moves
**current shapes as-is** (no behavior change); later tasks then edit only one
place. It also breaks the `pkg/policyserver` → `pkg/ca` import.

**Files:**
- Create: `pkg/wire/wire.go`
- Modify: `pkg/ca/ca.go` (delete `CertParams`, `PolicyResponse`, `DiscoveryResponse`, `BootstrapAuth`, `PolicyError`; use wire types)
- Modify: `pkg/policyserver/policyserver.go` (delete `Request`, `Response`, `DiscoveryResponse`, `PolicyError` + its constructors' internal type; use wire types)
- Modify: `pkg/policyserver/policy_config.go` (delete the `BootstrapAuth` struct; `BootstrapAuth()` methods return `wire.AuthConfig`)
- Modify: `pkg/caclient/caclient.go` (delete `Discovery`, `BootstrapAuth`; use wire types)
- Modify: `pkg/caserver/caserver.go`, `pkg/policyserver/evaluator/evaluator.go`, `pkg/broker/auth.go`, `cmd/epithet/agent.go`, `cmd/epithet/policy.go` (update references)
- Test: `pkg/wire/wire_test.go`

**Interfaces:**
- Produces (every later task uses these):

```go
package wire

import (
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
)

// CertParams are the certificate parameters decided by the policy server.
type CertParams struct {
	Identity   string            `json:"identity"`
	Names      []string          `json:"principals"`
	Expiration time.Duration     `json:"expiration"`
	Extensions map[string]string `json:"extensions"`
}

// PolicyRequest is the CA→policy-server cert evaluation request body.
type PolicyRequest struct {
	Token      string            `json:"token"`
	Connection policy.Connection `json:"connection"`
}

// PolicyResponse is the policy server's answer to a PolicyRequest.
type PolicyResponse struct {
	CertParams CertParams    `json:"certParams"`
	Policy     policy.Policy `json:"policy"`
}

// AuthConfig tells a client how to authenticate. Shape matches today's
// BootstrapAuth; Type/Command/Scopes are removed by later tasks.
type AuthConfig struct {
	Type         string   `json:"type"`
	Issuer       string   `json:"issuer,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Command      string   `json:"command,omitempty"`
}

// Discovery is the discovery document.
type Discovery struct {
	Auth          *AuthConfig `json:"auth,omitempty"`
	MatchPatterns []string    `json:"matchPatterns,omitempty"`

	// CacheControl carries the upstream Cache-Control header; never serialized.
	CacheControl string `json:"-"`
}

// PolicyError is a policy-server error with its HTTP status.
type PolicyError struct {
	StatusCode int
	Message    string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("policy error %d: %s", e.StatusCode, e.Message)
}
```

**Migration notes (mechanical, but do them exactly):**
- `ca.RequestPolicy` currently builds its body as `map[string]any` (`ca.go:260`);
  replace with `wire.PolicyRequest{Token: token, Connection: conn}` — this is the
  typed-request fix from the spec.
- `ca.PolicyError` and `policyserver.PolicyError` both become `wire.PolicyError`.
  Grep for `ca.PolicyError` (`caserver.go` uses it in three `errors.As` sites) and
  `policyserver.PolicyError` (handler + `Forbidden`/`InternalError` constructors).
- `policyserver.Response` → `wire.PolicyResponse`; the `PolicyEvaluator` interface
  signature changes to return `*wire.PolicyResponse`.
- `pkg/policyserver` must no longer import `pkg/ca` (that was the point); verify
  with `grep -rn '"github.com/epithet-ssh/epithet/pkg/ca"' pkg/policyserver/`.
- `caclient.Discovery` → `wire.Discovery`; `caclient.BootstrapAuth` →
  `wire.AuthConfig`; `broker.AuthConfigToCommand` parameter becomes
  `wire.AuthConfig`.
- Keep `caclient`'s error types (`InvalidTokenError` etc.) where they are — they
  are client-side classifications, not wire shapes.

- [ ] **Step 1: Write the failing test**

```go
// pkg/wire/wire_test.go
package wire

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The JSON wire shape is a compatibility contract for third-party policy
// servers; pin it.
func TestPolicyRequestWireShape(t *testing.T) {
	req := PolicyRequest{Token: "tok"}
	out, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, `{"token":"tok","connection":{"localHost":"","remoteHost":"","remoteUser":"","port":0,"proxyJump":"","hash":""}}`, string(out))
}

func TestCertParamsRoundTrip(t *testing.T) {
	p := CertParams{Identity: "a@b.c", Names: []string{"root"}, Expiration: 5 * time.Minute}
	out, err := json.Marshal(p)
	require.NoError(t, err)
	var back CertParams
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, p.Identity, back.Identity)
	require.Equal(t, p.Expiration, back.Expiration)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/wire -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Create `pkg/wire/wire.go`** with the content from the Interfaces block above.

- [ ] **Step 4: Run the wire tests**

Run: `go test ./pkg/wire -v` — Expected: PASS.

- [ ] **Step 5: Migrate all consumers** per the migration notes. Delete the old
type definitions (do not alias). Chase compile errors with `make build` until the
tree builds. Update test files that referenced the old types
(`pkg/policyserver/policyserver_test.go`, `pkg/policyserver/policy_config_test.go`,
`pkg/broker/auth_test.go` `TestAuthConfigToCommand_*`, caserver/ca tests).

- [ ] **Step 6: Run full tests**

Run: `make build && make test`
Expected: PASS — behavior is unchanged; this is a pure type move.

- [ ] **Step 7: Checkpoint** — report; stop for review.

---

### Task 3: Delete the base64 token wrapping (lockstep, both sides)

**Files:**
- Modify: `pkg/broker/auth.go` (execute() returns raw stdout as token)
- Modify: `pkg/policyserver/policyserver.go` (`handleCertRequest` uses `req.Token` directly)
- Modify: `pkg/broker/auth_test.go` (delete `TestAuth_Run_BinaryTokenPreservation`; fix tests asserting encoded tokens)
- Modify: any test asserting base64 round-trip in `pkg/policyserver/policyserver_test.go`

**Interfaces:**
- Consumes: Task 2's `wire.PolicyRequest`.
- Produces: token strings flow verbatim from auth source → `Authorization: Bearer` → `PolicyRequest.Token` → validator. Every later task assumes this.

- [ ] **Step 1: Write the failing test**

```go
// pkg/policyserver/policyserver_test.go — add:
func TestHandlerAcceptsBareToken(t *testing.T) {
	h := NewHandler(Config{
		Validator: &mockValidator{identity: "alice@example.com"},
		Evaluator: &mockEvaluator{},
	})
	body, _ := json.Marshal(wire.PolicyRequest{Token: "raw.jwt.token"})
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}
```

(Adapt the mock names to what `policyserver_test.go` already defines — a
`mockValidator` exists at line ~24. If there is no `mockEvaluator`, reuse the
test file's existing evaluator stub.)

- [ ] **Step 2: Run it** — Expected: FAIL (handler rejects "raw.jwt.token" as invalid base64url — `.` is not in the alphabet).

- [ ] **Step 3: Implement.** In `policyserver.go` delete lines 208-214 (the decode +
error branch) and pass `req.Token` to the validator. In `broker/auth.go` change
`execute`'s return from `base64.RawURLEncoding.EncodeToString(token)` to
`string(token)`, delete the `encoding/base64` import, and update the doc comment
(stdout is the token, sent verbatim).

- [ ] **Step 4: Fix the broker tests.** Delete
`TestAuth_Run_BinaryTokenPreservation` (`pkg/broker/auth_test.go:353`) — binary
tokens are no longer a supported concept. Any test comparing
`base64.RawURLEncoding.EncodeToString(...)` against `Run`'s result now compares
the raw string.

- [ ] **Step 5: Run tests**

Run: `make test && go test -race ./pkg/broker`
Expected: PASS.

- [ ] **Step 6: Checkpoint** — report; stop for review.

---

### Task 4: Harden the OIDC validator; delete the `TokenValidator` interface

**Files:**
- Modify: `pkg/policyserver/oidc/validator.go`
- Modify: `pkg/policyserver/policyserver.go` (Config takes `*oidc.Validator`; handler threads `r.Context()` and claims)
- Modify: `pkg/policyserver/evaluator/evaluator.go` (constructors; delete stored `validator` field)
- Modify: `cmd/epithet/policy.go` (drop the `policyserver.TokenValidator` variable type)
- Modify: `pkg/policyserver/oidc/validator_test.go` (rewrite against `pkg/oidctest`)
- Modify: `pkg/policyserver/policyserver_test.go` (mock validator replaced — see note)

**Interfaces:**
- Consumes: `oidctest.IdP` (Task 1).
- Produces (used by Tasks 5, 8, 14):

```go
// pkg/policyserver/oidc — final surface:
type Config struct {
	Issuer    string
	ClientID  string           // now required
	TLSConfig tlsconfig.Config
}
type Claims struct {
	Identity  string    // email claim, falling back to sub
	ExpiresAt time.Time
}
func NewValidator(ctx context.Context, config Config) (*Validator, error)
func (v *Validator) Validate(ctx context.Context, token string) (*Claims, error)
```

Deleted: `ValidateAndExtractIdentity`, `ValidateAccessToken`, `SkipExpiryCheck`,
the `SkipClientIDCheck` fallback, `Claims.{Email,Subject,Issuer,Audience,IssuedAt}`,
`policyserver.TokenValidator`.

**Note on the handler seam:** `policyserver.Config.Validator` becomes the concrete
`*oidc.Validator`. The existing `mockValidator` in `policyserver_test.go` can no
longer implement an interface — handler unit tests instead construct a real
validator against `oidctest.New(t)` and mint real tokens. That is the point of
Task 1.

- [ ] **Step 1: Write failing validator tests**

```go
// pkg/policyserver/oidc/validator_test.go — replace file content:
package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func newValidator(t *testing.T, idp *oidctest.IdP) *Validator {
	v, err := NewValidator(context.Background(), Config{
		Issuer:   idp.Issuer(),
		ClientID: oidctest.ClientID,
	})
	require.NoError(t, err)
	return v
}

func TestValidateReturnsIdentityAndExpiry(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)

	exp := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	claims, err := v.Validate(context.Background(), idp.MintIDToken("alice@example.com", exp))
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", claims.Identity)
	require.WithinDuration(t, exp, claims.ExpiresAt, time.Second)
}

func TestValidateRejectsExpiredToken(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)
	_, err := v.Validate(context.Background(), idp.MintIDToken("alice@example.com", time.Now().Add(-time.Minute)))
	require.Error(t, err)
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	idp := oidctest.New(t)
	v := newValidator(t, idp)
	tok := idp.MintIDTokenWithAudience("alice@example.com", "someone-else", time.Now().Add(time.Minute))
	_, err := v.Validate(context.Background(), tok)
	require.Error(t, err)
}

func TestNewValidatorRequiresClientID(t *testing.T) {
	idp := oidctest.New(t)
	_, err := NewValidator(context.Background(), Config{Issuer: idp.Issuer()})
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_id")
}
```

Note: the fake IdP serves plain HTTP (`httptest.NewServer`), so `tlsconfig` needs
no special handling; keep `TLSConfig` zero-valued in tests. The unused import
above should be dropped if the compiler complains.

- [ ] **Step 2: Run** `go test ./pkg/policyserver/oidc -v` — Expected: FAIL (`TestNewValidatorRequiresClientID` — empty ClientID currently silently skips the audience check; `TestValidateRejectsWrongAudience` may pass or fail depending on old config — the compile break from the new `Claims` shape comes first).

- [ ] **Step 3: Implement.** In `validator.go`: require `ClientID` in
`NewValidator` (`return nil, fmt.Errorf("client_id is required")`), delete the
`SkipClientIDCheck` else-branch and `SkipExpiryCheck`, trim `Claims` to
`{Identity, ExpiresAt}`, delete `ValidateAndExtractIdentity` and
`ValidateAccessToken` (and the now-unused `oauth2` import and `issuer` field if
nothing reads it). `Validate` keeps its signature; identity extraction (email →
sub fallback) is unchanged.

- [ ] **Step 4: Rewire the handler.** In `policyserver.go`:

```go
// Config (partial):
Validator *oidc.Validator

// handleCertRequest (replacing the ValidateAndExtractIdentity call):
claims, err := h.config.Validator.Validate(r.Context(), req.Token)
if err != nil {
	h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Invalid token: %v", err))
	return
}
resp, err := h.config.Evaluator.Evaluate(r.Context(), claims.Identity, req.Connection)
```

Delete the `TokenValidator` interface. In `evaluator.go`: delete the `validator`
struct field (constructors still create and return the validator — their
signatures are unchanged). In `cmd/epithet/policy.go:73` change
`var validator policyserver.TokenValidator` to `var validator *oidc.Validator`
(import `pkg/policyserver/oidc`).

- [ ] **Step 5: Rewrite handler unit tests** in `policyserver_test.go` to build a
real validator from `oidctest` and mint tokens for the success/401 paths.

- [ ] **Step 6: Run tests** — `make build && make test` — Expected: PASS.

- [ ] **Step 7: Checkpoint** — report; stop for review.

---

### Task 5: Evaluator — deterministic matching, single pass, `Rules` merge

**Files:**
- Modify: `pkg/policyserver/policy_config.go` (merge `DefaultPolicy`/`HostPolicy` into `Rules`)
- Modify: `pkg/policyserver/loader.go` (references to the merged type)
- Modify: `pkg/policyserver/evaluator/evaluator.go`
- Test: `pkg/policyserver/evaluator/evaluator_test.go`

**Interfaces:**
- Produces (used by Task 6):

```go
// policy_config.go:
type Rules struct {
	Allow      map[string][]string `yaml:"allow,omitempty" json:"allow,omitempty"`
	Expiration string              `yaml:"expiration,omitempty" json:"expiration,omitempty"`
	Extensions map[string]string   `yaml:"extensions,omitempty" json:"extensions,omitempty"`
}
// PolicyConfig.Defaults *Rules; PolicyConfig.Hosts map[string]*Rules
```

- Matching becomes deterministic: patterns are evaluated **longest pattern string
  first, ties broken lexicographically**. Document this in a comment — YAML maps
  cannot preserve author order, so specificity-by-length is the deterministic
  proxy.

- [ ] **Step 1: Write the failing determinism test**

```go
// pkg/policyserver/evaluator/evaluator_test.go — add:
func TestHostRuleSelectionIsDeterministic(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{"alice@example.com": {"admin"}},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{"root": {"admin"}}, Expiration: "30m",
		},
		Hosts: map[string]*policyserver.Rules{
			"*.example.com":      {Expiration: "30m"},
			"prod-*.example.com": {Expiration: "2m"},
		},
	}
	e := evaluatorForConfig(cfg) // helper: construct evaluator with static policy, no validator
	conn := policy.Connection{RemoteHost: "prod-db.example.com", RemoteUser: "root"}

	// Run many times: map iteration order must not leak into the result.
	for range 50 {
		resp, err := e.Evaluate(context.Background(), "alice@example.com", conn)
		require.NoError(t, err)
		require.Equal(t, 2*time.Minute, resp.CertParams.Expiration,
			"longest (most specific) pattern must always win")
	}
}
```

(`evaluatorForConfig` wraps whatever constructor pattern the existing test file
uses — follow it. If no static-policy test helper exists, use
`NewForTestingWithProvider(policyserver.NewStaticProvider(cfg))`.)

- [ ] **Step 2: Run** `go test ./pkg/policyserver/evaluator -run Deterministic -count=5 -v`
Expected: FAIL intermittently (map order) — the `-count=5` improves the odds of
catching the flake; it may take a re-run to see it fail. The type errors from
`Rules` come first.

- [ ] **Step 3: Implement.**
  1. In `policy_config.go`: define `Rules`, delete `DefaultPolicy` and
     `HostPolicy`, update `PolicyConfig`/`PolicyRulesConfig` fields and
     `Validate()`. Grep `DefaultPolicy\|HostPolicy` across the repo
     (`loader.go`, `cmd/epithet/policy.go:188`, tests) and update.
  2. In `evaluator.go`: add

```go
// sortedHostPatterns returns host patterns longest-first (ties lexicographic).
// YAML maps cannot preserve order, so pattern length is the deterministic
// specificity proxy; a longer pattern must never lose to a shorter one by
// map-iteration luck.
func sortedHostPatterns(hosts map[string]*policyserver.Rules) []string {
	patterns := make([]string, 0, len(hosts))
	for p := range hosts {
		patterns = append(patterns, p)
	}
	slices.SortFunc(patterns, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	return patterns
}
```

  3. Collapse the three `Hosts` walks in `Evaluate` into a **single pass** over
     `sortedHostPatterns`: one loop that (a) records the first matching pattern's
     `Rules` (expiration/extensions), (b) accumulates `hostUsers`, and reuses the
     result for `isAuthorized` (check `hostUsers` after the loop). Delete the
     separate `isAuthorized` loop's own matching; it operates on the computed map.
     Also delete the `isHelloRequest` branch (`evaluator.go:110-121`) — Hello
     dies in Task 8, and empty-connection requests are simply not authorized.

- [ ] **Step 4: Run tests** — `go test ./pkg/policyserver/... -count=5` then `make test` — Expected: PASS, deterministic.

- [ ] **Step 5: Checkpoint** — report; stop for review.

---

### Task 6: Cert TTL clamp — `NotAfter` through to signing

**Files:**
- Modify: `pkg/wire/wire.go` (CertParams gains `NotAfter`)
- Modify: `pkg/policyserver/policyserver.go` (thread token expiry into Evaluate)
- Modify: `pkg/policyserver/evaluator/evaluator.go` (set `NotAfter`)
- Modify: `pkg/ca/ca.go` (`SignPublicKey` clamps)
- Test: `pkg/ca/ca_test.go`, `pkg/policyserver/evaluator/evaluator_test.go`

**Interfaces:**
- `wire.CertParams` gains `NotAfter time.Time \`json:"notAfter,omitempty"\`` —
  an absolute ceiling; zero value means "no ceiling".
- `PolicyEvaluator` interface becomes:

```go
Evaluate(ctx context.Context, identity string, tokenExpiry time.Time, conn policy.Connection) (*wire.PolicyResponse, error)
```

- `ca.SignPublicKey`: `ValidBefore = min(now+Expiration, NotAfter)` when
  `NotAfter` is non-zero.

- [ ] **Step 1: Write failing tests**

```go
// pkg/ca/ca_test.go — add (follow the file's existing key fixtures):
func TestSignPublicKeyClampsToNotAfter(t *testing.T) {
	c := newTestCA(t) // reuse the file's existing CA construction helper
	notAfter := time.Now().Add(90 * time.Second)
	cert := signTestCert(t, c, &wire.CertParams{
		Identity:   "alice@example.com",
		Names:      []string{"root"},
		Expiration: 10 * time.Minute, // would outlive the token
		NotAfter:   notAfter,
	})
	require.LessOrEqual(t, cert.ValidBefore, uint64(notAfter.Unix()))
}

func TestSignPublicKeyUsesExpirationWhenNoNotAfter(t *testing.T) {
	c := newTestCA(t)
	cert := signTestCert(t, c, &wire.CertParams{
		Identity: "alice@example.com", Names: []string{"root"}, Expiration: 5 * time.Minute,
	})
	require.Greater(t, cert.ValidBefore, uint64(time.Now().Add(4*time.Minute).Unix()))
}
```

```go
// evaluator_test.go — add:
func TestEvaluateSetsNotAfterFromTokenExpiry(t *testing.T) {
	e := evaluatorForConfig(basicConfig()) // reuse Task 5 helpers
	exp := time.Now().Add(3 * time.Minute)
	resp, err := e.Evaluate(context.Background(), "alice@example.com", exp,
		policy.Connection{RemoteHost: "web.example.com", RemoteUser: "root"})
	require.NoError(t, err)
	require.Equal(t, exp, resp.CertParams.NotAfter)
}
```

- [ ] **Step 2: Run** — Expected: FAIL (no `NotAfter` field; Evaluate arity).

- [ ] **Step 3: Implement.**
  - `wire.CertParams`: add the field.
  - `evaluator.Evaluate`: new `tokenExpiry time.Time` parameter; set
    `CertParams.NotAfter = tokenExpiry` in `buildResponseWithHostUsers` (thread
    the value through; add the parameter to that helper).
  - `policyserver.handleCertRequest`:
    `h.config.Evaluator.Evaluate(r.Context(), claims.Identity, claims.ExpiresAt, req.Connection)`;
    update the `PolicyEvaluator` interface.
  - `ca.SignPublicKey`:

```go
validBefore := time.Now().Add(params.Expiration)
if !params.NotAfter.IsZero() && params.NotAfter.Before(validBefore) {
	// The certificate must never outlive the auth session that requested it.
	validBefore = params.NotAfter
}
certificate.ValidBefore = uint64(validBefore.Unix())
```

  Also reject a ceiling already in the past: if `NotAfter` is non-zero and before
  `time.Now()`, return an error (`fmt.Errorf("certificate NotAfter %s is in the past", params.NotAfter)`).

- [ ] **Step 4: Run tests** — `make test` — Expected: PASS.

- [ ] **Step 5: Checkpoint** — report; stop for review.

---

### Task 7: `pkg/serviceauth` — CA-minted JWT replaces RFC 9421

**Files:**
- Create: `pkg/serviceauth/serviceauth.go`
- Test: `pkg/serviceauth/serviceauth_test.go`
- Modify: `pkg/ca/ca.go` (sign with serviceauth; delete httpsig)
- Modify: `pkg/policyserver/policyserver.go` (verify with serviceauth, now **required**; `NewHandler` returns error)
- Modify: `cmd/epithet/policy.go` (handle `NewHandler` error)
- Delete: `pkg/httpsig/` (whole package + its tests)
- Modify: `go.mod` (drop `yaronf/httpsign`; `go mod tidy`)

**Interfaces:**
- Produces:

```go
package serviceauth

// Audience is the aud claim on every service token.
const Audience = "epithet-policy"

// TokenTTL bounds how long a minted request token is accepted.
const TokenTTL = 60 * time.Second

type Signer struct{ /* jose.Signer + key fingerprint */ }
func NewSigner(privateKey sshcert.RawPrivateKey) (*Signer, error)
// Authorize mints a request-bound JWT and sets the Authorization header.
// body may be nil (GET); the bh claim is then over the empty string.
func (s *Signer) Authorize(req *http.Request, body []byte) error

type Verifier struct{ /* crypto.PublicKey + expected alg */ }
func NewVerifier(publicKey sshcert.RawPublicKey) (*Verifier, error)
// Verify checks the Authorization header's JWT: signature, aud, exp/iat
// freshness, and that bh matches sha256(body).
func (v *Verifier) Verify(authHeader string, body []byte) error
```

- Claims: `iss` = SHA256 ssh fingerprint of the CA key, `aud`, `iat`, `exp`
  (= iat + TokenTTL), `jti` (random hex; minted for future replay detection, not
  checked), `bh` = `base64.RawURLEncoding(sha256(body))`.
- Key→alg mapping (the one switch that survives httpsig): ed25519→`EdDSA`,
  RSA→`PS256`, ECDSA P-256→`ES256`, P-384→`ES384`. Implement with
  `go-jose/v4` (`jose.NewSigner`, `jwt.Signed(...).Claims(...).Serialize()`,
  verify via `jwt.ParseSigned` restricted to the single expected algorithm and
  `Claims(pubKey, &out)`).

- [ ] **Step 1: Write failing tests**

```go
// pkg/serviceauth/serviceauth_test.go
package serviceauth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
)

func keyPair(t *testing.T) (sshcert.RawPublicKey, sshcert.RawPrivateKey) {
	t.Helper()
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	return pub, priv
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv := keyPair(t)
	s, err := NewSigner(priv)
	require.NoError(t, err)
	v, err := NewVerifier(pub)
	require.NoError(t, err)

	body := []byte(`{"token":"x"}`)
	req, _ := http.NewRequest("POST", "http://policy/", strings.NewReader(string(body)))
	require.NoError(t, s.Authorize(req, body))
	require.NoError(t, v.Verify(req.Header.Get("Authorization"), body))
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	pub, priv := keyPair(t)
	s, _ := NewSigner(priv)
	v, _ := NewVerifier(pub)
	req, _ := http.NewRequest("POST", "http://policy/", nil)
	require.NoError(t, s.Authorize(req, []byte("original")))
	require.Error(t, v.Verify(req.Header.Get("Authorization"), []byte("tampered")))
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := keyPair(t)
	otherPub, _ := keyPair(t)
	s, _ := NewSigner(priv)
	v, _ := NewVerifier(otherPub)
	req, _ := http.NewRequest("GET", "http://policy/", nil)
	require.NoError(t, s.Authorize(req, nil))
	require.Error(t, v.Verify(req.Header.Get("Authorization"), nil))
}

func TestVerifyRejectsMissingHeader(t *testing.T) {
	pub, _ := keyPair(t)
	v, _ := NewVerifier(pub)
	require.Error(t, v.Verify("", nil))
}
```

Also add an expiry test by minting with a hacked `TokenTTL` — expose an internal
`authorizeAt(req, body, now time.Time)` used by `Authorize` so the test can mint
an already-expired token without sleeping.

- [ ] **Step 2: Run** `go test ./pkg/serviceauth -v` — Expected: FAIL (package missing).

- [ ] **Step 3: Implement `serviceauth.go`.** Key parsing mirrors what httpsig did:
`ssh.ParseRawPrivateKey` / `ssh.ParseAuthorizedKey` +
`ssh.CryptoPublicKey().CryptoPublicKey()`, then the four-arm alg switch. Verify
enforces: parse restricted to the expected alg, `aud == Audience`, `exp` in the
future, `iat` no more than `TokenTTL+30s` in the past (clock-skew grace), `bh`
equality via `crypto/subtle.ConstantTimeCompare`.

- [ ] **Step 4: Run** `go test ./pkg/serviceauth -v` — Expected: PASS.

- [ ] **Step 5: Swap the CA side.** In `ca.go`: replace `httpSigner *httpsig.Signer`
with `svcSigner *serviceauth.Signer`; in `RequestPolicy` and `FetchDiscovery`
replace `c.httpSigner.SignRequest(req)` with `c.svcSigner.Authorize(req, body)`
(`body` is the marshaled request for POST, `nil` for GET).

- [ ] **Step 6: Swap the policy-server side.** In `policyserver.go`:

```go
// Config: CAPublicKey is now required.
func NewHandler(config Config) (http.Handler, error) {
	if config.CAPublicKey == "" {
		return nil, fmt.Errorf("CAPublicKey is required")
	}
	verifier, err := serviceauth.NewVerifier(config.CAPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid CA public key: %w", err)
	}
	...
}
```

`ServeHTTP` reads the body **once** up front (`io.ReadAll(io.LimitReader(...))`),
calls `h.verifier.Verify(r.Header.Get("Authorization"), body)`, 401s on failure,
then dispatches with the already-read body (pass `body []byte` into
`handleCertRequest`; GET passes `nil`). This removes the double body read that
Content-Digest used to require. Update `cmd/epithet/policy.go:135` for the new
`(handler, err)` return.

- [ ] **Step 7: Delete `pkg/httpsig/`** entirely; `go mod tidy` (drops
`yaronf/httpsign`, `dunglas/httpsfv`). Update the policyserver tests that built
signed requests to use `serviceauth.NewSigner` with a test key.

- [ ] **Step 8: Run tests** — `make build && make test` — Expected: PASS.

- [ ] **Step 9: Checkpoint** — report; stop for review.

---

### Task 8: Server-side discovery — anonymous bootstrap only; delete Hello/probe

**Files:**
- Modify: `pkg/wire/wire.go` (`AuthConfig` loses `Type`/`Command`/`Scopes`; `Discovery` loses `MatchPatterns`)
- Modify: `pkg/policyserver/policy_config.go` (`BootstrapAuth()` methods return the slim shape; delete `DefaultScopes`, `OIDCConfig.Scopes`)
- Modify: `pkg/policyserver/loader.go` + wherever `HostPatterns()` is defined (delete it)
- Modify: `cmd/epithet/policy.go` (discovery built from `ServerConfig` only)
- Modify: `pkg/caserver/caserver.go` (DiscoveryHandler = pass-through; delete `handleHello`, hello routing, `setDiscoveryLink`, `Vary`; `CreateCertRequest` fields become non-pointer; extract `fail` helper)
- Modify: `pkg/ca/ca.go` (drop `discoveryClient`/httpcache; single client)
- Modify: `pkg/broker/auth.go` (delete `AuthConfigToCommand` — it switches on the deleted `Type`; the broker keeps compiling because `cmd/epithet/agent.go` is updated in the same task)
- Modify: `cmd/epithet/agent.go` (temporary shim — see Step 5)
- Tests: `pkg/caserver/caserver_test.go`, `pkg/policyserver/*_test.go`

**Interfaces:**
- `wire.AuthConfig` final shape: `{Issuer, ClientID, ClientSecret}` (json:
  `issuer`, `client_id`, `client_secret,omitempty`).
- `wire.Discovery` final shape: `{Auth *AuthConfig; CacheControl string \`json:"-"\`}`.
- `caserver.CreateCertRequest` final shape:

```go
type CreateCertRequest struct {
	PublicKey  sshcert.RawPublicKey `json:"publicKey"`
	Connection policy.Connection    `json:"connection"`
}
```

  `createCert` rejects requests where either is empty (400) — the both-absent
  hello shape is gone.

- [ ] **Step 1: Write the failing caserver test**

```go
// pkg/caserver/caserver_test.go — add:
func TestDiscoveryIsAnonymousPassThrough(t *testing.T) {
	// Stub policy server returning a slim discovery doc.
	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Cache-Control", "max-age=120")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"auth":{"issuer":"https://idp.example.com","client_id":"cid"}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer policySrv.Close()

	c := newTestCAWithPolicyURL(t, policySrv.URL) // follow the file's existing construction pattern
	srv := New(c, slog.New(slog.DiscardHandler), nil, nil)

	req := httptest.NewRequest("GET", "/discovery", nil) // no Authorization header
	rec := httptest.NewRecorder()
	srv.DiscoveryHandler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "max-age=120", rec.Header().Get("Cache-Control"))
	var d wire.Discovery
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &d))
	require.Equal(t, "https://idp.example.com", d.Auth.Issuer)
	require.Empty(t, rec.Header().Get("Vary"))
}
```

- [ ] **Step 2: Run** — Expected: FAIL (compile: `wire.Discovery` still has MatchPatterns is fine, but the handler still runs the token-probe branch and sets `Vary`).

- [ ] **Step 3: Slim the wire types.** Remove `Type`, `Command`, `Scopes` from
`wire.AuthConfig`; remove `MatchPatterns` from `wire.Discovery`. In
`policy_config.go`: `BootstrapAuth()` (both copies — delete the
`PolicyRulesConfig` one, it is test-only per the spec inventory) returns
`wire.AuthConfig{Issuer: c.OIDC.Issuer, ClientID: c.OIDC.ClientID, ClientSecret: c.OIDC.ClientSecret}`;
delete `DefaultScopes()` and `OIDCConfig.Scopes`. Delete `HostPatterns()`
(defined on `PolicyConfig` — find with `grep -rn "func.*HostPatterns" pkg/`).

- [ ] **Step 4: Rewrite the caserver.** In `caserver.go`:
  - `DiscoveryHandler`: fetch via `s.c.FetchDiscovery(r.Context())`, marshal
    `wire.Discovery{Auth: discovery.Auth}`, set Cache-Control passthrough
    (fallback `max-age=300`), done. No token parsing, no probe, no `Vary`.
  - Delete `handleHello`, the hello routing in `createCert`
    (`caserver.go:236-248`), and `setDiscoveryLink` + every call site — the Link
    header is dead (clients derive `/discovery`).
  - `CreateCertRequest` fields become non-pointer values; `createCert` returns
    400 if `ccr.PublicKey == ""` or `ccr.Connection.RemoteHost == ""`.
  - Extract the error-write boilerplate:

```go
// fail writes a plain-text error response.
func (s *caServer) fail(w http.ResponseWriter, code int, format string, args ...any) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	fmt.Fprintf(w, format, args...)
}
```

    and replace all 19 hand-rolled sites.
  - In `ca.go`: delete `discoveryClient`, the two `httpcache.NewMemoryCacheTransport()`
    constructions, and the `gregjones/httpcache` import; `FetchDiscovery` uses
    `c.httpClient`. Keep the unix-socket dial branch (single transport now).

- [ ] **Step 5: Keep the client compiling (temporary shim).** `AuthConfigToCommand`
switches on the deleted `Type` field — delete the function now
(`pkg/broker/auth.go:328-378`) and, in `cmd/epithet/agent.go`, replace the
discovery→command block (`agent.go:114-141`) with a temporary hardcoded command
build (this whole path is rewritten properly in Task 11):

```go
// TEMPORARY until Task 11: build the oidc exec command inline.
authCommand := parent.Auth
if authCommand == "" {
	discovery, err := caClient.GetDiscovery(context.Background(), "")
	if err != nil || discovery == nil || discovery.Auth == nil {
		return fmt.Errorf("failed to get discovery config: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	authCommand = fmt.Sprintf("%s auth oidc --issuer %s --client-id %s", exe, discovery.Auth.Issuer, discovery.Auth.ClientID)
	if discovery.Auth.ClientSecret != "" {
		authCommand += " --client-secret " + discovery.Auth.ClientSecret
	}
}
```

Delete the `TestAuthConfigToCommand_*` tests in `pkg/broker/auth_test.go`.

- [ ] **Step 6: Update policy-server discovery wiring.** In `cmd/epithet/policy.go`
delete `matchPatterns := initialPolicy.HostPatterns()` and build
`discovery := &wire.Discovery{Auth: &authConfig}`; drop `match_patterns` from the
startup log line. In `policyserver.go`, `Config.Discovery` becomes
`*wire.Discovery` and `handleDiscovery` is unchanged apart from the type.

- [ ] **Step 7: Run tests** — `make build && make test`. Broker unit tests
touching `shouldHandle`/discovery patterns still pass (client side untouched
apart from the shim; `GetDiscovery` still exists). Integration `test/sshd` uses a
stub policy server that returns `type: command` — update its stub to serve the
slim shape and expect the temporary-shim behavior to fail auth; **if it cannot
pass in this intermediate state, mark it `t.Skip("rewired in Task 14")` with a
comment** rather than contorting it.
Expected: PASS (with the possible documented skip).

- [ ] **Step 8: Checkpoint** — report; stop for review.

---

### Task 8b: Delete dynamic policy loading

Per spec §12: `--policy-source`, the loader, and the provider indirection go.
epithet-aws is reworked separately (Task 16 files the yatl task).

**Files:**
- Delete: `pkg/policyserver/loader.go`, `pkg/policyserver/loader_test.go`
- Modify: `pkg/policyserver/policyserver.go` (delete `PolicyProvider`, `LoaderProvider`, `StaticProvider` if defined there — grep `NewStaticProvider\|NewLoaderProvider\|PolicyProvider` for the actual homes)
- Modify: `pkg/policyserver/evaluator/evaluator.go` (one constructor path)
- Modify: `cmd/epithet/policy.go` (single-arm setup; delete `--policy-source`)
- Modify: `pkg/policyserver/evaluator/evaluator_test.go` (constructor renames)

**Interfaces:**
- `evaluator.Evaluator` holds a `*policyserver.PolicyConfig` directly (no
  provider). Constructors collapse to:

```go
// New creates the evaluator and its OIDC validator.
func New(ctx context.Context, serverCfg *policyserver.ServerConfig, policyCfg *policyserver.PolicyConfig, tlsCfg tlsconfig.Config) (*Evaluator, *oidc.Validator, error)

// NewForTesting creates an evaluator without a validator.
func NewForTesting(policyCfg *policyserver.PolicyConfig) *Evaluator
```

  Delete `NewWithProvider`, `NewForTestingWithProvider`, `getPolicy` (the config
  is a field read), and the `staticPolicy`/`policyProvider` field pair.

- [ ] **Step 1: Delete `loader.go`/`loader_test.go`** and the provider types;
chase compile errors: `cmd/epithet/policy.go` loses the `if c.PolicySource != ""`
arm entirely — `Run` becomes: build `ServerConfig` → `loadInlinePolicy` →
validate → `evaluator.New(ctx, serverCfg, cfg.ExtractPolicyConfig(), tlsCfg)` →
handler → serve. Delete the `PolicySource` CLI field and `ServerConfig.PolicyURL`.
- [ ] **Step 2: Update evaluator tests** for the new constructor names (the
Task 5 helper `evaluatorForConfig` becomes a thin call to `NewForTesting`).
- [ ] **Step 3: Run** — `make build && make test` — Expected: PASS.
- [ ] **Step 4: Checkpoint** — report; stop for review.

---

### Task 9: caclient — one HTTP client, direct `/discovery`, delete Hello

**Files:**
- Modify: `pkg/caclient/caclient.go`
- Modify: `pkg/broker/broker.go` (`getDiscoveryPatterns`/`shouldHandle` — deleted here, see Step 4)
- Modify: `pkg/broker/broker_test.go`, `pkg/caclient/caclient_test.go`
- Modify: `cmd/epithet/agent.go` (drop the `GetPublicKey` pre-fetch)

**Interfaces:**
- `caclient.Client` final surface (consumed by Tasks 11, 14):
  - `New(endpoints []CAEndpoint, options ...Option) (*Client, error)` — options: `WithLogger`, `WithTLSConfig`, `WithTimeout`, `WithCooldown` (delete `WithHTTPClient`).
  - `GetCert(ctx, token string, req *caserver.CreateCertRequest) (*CertResponse, error)` — unchanged behavior; `CertResponse` loses `DiscoveryURL`.
  - `GetDiscovery(ctx context.Context) (*wire.Discovery, error)` — **no token
    parameter**; GETs `<caURL>/discovery` through the breaker pool
    (`strings.TrimSuffix(caURL, "/") + "/discovery"`).
  - `GetPublicKey(ctx) (string, error)` — kept, minus Link parsing.
- Deleted: `Hello`, `doHello`, `fetchDiscovery`'s token handling,
  `SetDiscoveryURL`, `parseLinkHeader`, `discoveryClient`, `discoveryMu`/
  `discoveryURL`, `WithHTTPClient`, the `httpcache` import.

- [ ] **Step 1: Write the failing test**

```go
// pkg/caclient/caclient_test.go — add:
func TestGetDiscoveryHitsDiscoveryPathUnauthenticated(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"auth":{"issuer":"https://idp","client_id":"cid"}}`)
	}))
	defer srv.Close()

	c, err := New([]CAEndpoint{{URL: srv.URL, Priority: 0}})
	require.NoError(t, err)

	d, err := c.GetDiscovery(context.Background())
	require.NoError(t, err)
	require.Equal(t, "/discovery", gotPath)
	require.Empty(t, gotAuth, "discovery must be anonymous")
	require.Equal(t, "https://idp", d.Auth.Issuer)
}
```

- [ ] **Step 2: Run** — Expected: FAIL (`GetDiscovery` takes a token and returns nil without a cached URL).

- [ ] **Step 3: Implement the caclient changes** per the interface block. The new
`GetDiscovery` goes through `c.pool.Execute` like `GetCert` (this closes the
breaker-bypass bug); error mapping mirrors `doGetPublicKey` (5xx →
`CAUnavailableError`, else `InvalidRequestError`; no 401 case — the endpoint is
anonymous). Discovery responses are not HTTP-cached anymore; callers cache.

- [ ] **Step 4: Delete broker-side gating.** In `broker.go`: delete `shouldHandle`
(`:466-497`), `getDiscoveryPatterns` (`:499-545`), the Step-1 block in
`MatchWithUserOutput` (`:228-233`), the `doublestar` import, and the
`DiscoveryPatterns` fetch inside `Inspect` (`:696-702`) plus the
`InspectResponse.DiscoveryPatterns` field and its uses in
`grpc_server.go:121` and `cmd/epithet/inspect.go`. The proto field
`discovery_patterns` stays in the schema (never edit `pkg/brokerv1`); the Go
server just stops populating it. Delete broker tests covering shouldHandle
pattern matching. `pkg/policy.Policy.Matches` is still used by the cert store —
leave `pkg/policy` alone except confirming nothing else referenced the deleted
paths.

- [ ] **Step 5: Update `cmd/epithet/agent.go`**: delete the
`caClient.GetPublicKey` pre-fetch (it existed to learn the Link header) and call
`caClient.GetDiscovery(context.Background())` directly in the shim from Task 8.

- [ ] **Step 6: Run tests** — `make build && make test && go test -race ./pkg/broker` — Expected: PASS.

- [ ] **Step 7: Checkpoint** — report; stop for review.

---

### Task 10: `pkg/auth/oidc` becomes a library; delete the `auth` subcommand

**Files:**
- Modify: `pkg/auth/oidc/oidc.go`
- Create: `pkg/auth/oidc/oidc_test.go`
- Delete: `cmd/epithet/auth.go`, `cmd/epithet/auth_oidc.go`
- Modify: `cmd/epithet/main.go` (remove the `Auth AuthCLI` command)
- Modify: `cmd/epithet/agent.go` (the Task-8 shim now breaks — replace with a stub error; fully wired in Task 11 — or fold Task 11 in here if executing inline. If task-by-task: change the shim to return `fmt.Errorf("agent wiring updated in next task")` ONLY if unavoidable; prefer doing Step 5 below which keeps it working)

**Interfaces:**
- Produces (consumed by Tasks 11, 14):

```go
package oidc

// Scopes is fixed: nothing in epithet consumes claims beyond email/sub.
var Scopes = []string{"openid", "profile", "email"}

type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string // Optional for PKCE.
	TLSConfig    tlsconfig.Config
}

// Authenticate returns a fresh ID token. prev carries refresh state from the
// previous call (nil on first use); the returned token is the next state.
// User-facing progress ("visit this URL…") is written to out.
func Authenticate(ctx context.Context, cfg Config, prev *oauth2.Token, out io.Writer) (idToken string, next *oauth2.Token, err error)
```

- [ ] **Step 1: Write the failing test** — this is the browser-flow-without-a-browser test:

```go
// pkg/auth/oidc/oidc_test.go
package oidc

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateCompletesCodeFlowViaAutoApprovingIdP(t *testing.T) {
	idp := oidctest.New(t)
	cfg := Config{IssuerURL: idp.Issuer(), ClientID: oidctest.ClientID}

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The flow prints "To authenticate, visit: <url>"; a goroutine plays the
	// browser by GETting that URL, which the fake IdP auto-approves.
	done := make(chan struct{})
	go func() {
		defer close(done)
		urlRe := regexp.MustCompile(`visit: (\S+)`)
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if m := urlRe.FindSubmatch(out.Bytes()); m != nil {
				resp, err := http.Get(string(m[1]))
				if err == nil {
					resp.Body.Close()
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	idToken, next, err := Authenticate(ctx, cfg, nil, &out)
	<-done
	require.NoError(t, err)
	require.NotEmpty(t, idToken)
	require.NotNil(t, next)
	require.Contains(t, idToken, ".") // it is a JWT
}

func TestAuthenticateReusesValidToken(t *testing.T) {
	idp := oidctest.New(t)
	cfg := Config{IssuerURL: idp.Issuer(), ClientID: oidctest.ClientID}
	prev := &oauth2.Token{AccessToken: "still-good", Expiry: time.Now().Add(time.Hour)}
	prev = prev.WithExtra(map[string]any{"id_token": idp.MintIDToken("x@y.z", time.Now().Add(time.Hour))})

	idToken, _, err := Authenticate(context.Background(), cfg, prev, io.Discard)
	require.NoError(t, err)
	require.NotEmpty(t, idToken)
}
```

Note the reuse path: today `Run` reuses `token.Valid()` state but re-extracts
`id_token` from `newToken.Extra` — a reused `oauth2.Token` round-tripped through
JSON keeps `id_token` only if stored via `WithExtra` before marshal; since state
now stays in memory as a live `*oauth2.Token`, `Extra("id_token")` keeps working.
Preserve exactly today's three-way logic (valid → reuse; refresh token → refresh;
else full flow).

- [ ] **Step 2: Run** `go test ./pkg/auth/oidc -v` — Expected: FAIL (`Authenticate` undefined).

- [ ] **Step 3: Refactor `oidc.go`.** Rename `Run` → `Authenticate` with the new
signature: delete the stdin state read (use `prev`), the stdout token write and
fd-3 state write (return them), and the package-level `userOutput = os.NewFile(4, …)`
(replace `notifyUser` with writes to the `out` parameter — thread `out` into
`performFullAuth`). Browser-open failure messages go to `out` too, not stderr.
Config loses `Scopes` (use the package `Scopes` var in the oauth2 config).

- [ ] **Step 4: Delete the CLI.** Remove `cmd/epithet/auth.go` and
`cmd/epithet/auth_oidc.go`; remove `Auth AuthCLI` from the `cli` struct in
`main.go:48`.

- [ ] **Step 5: Keep the agent working.** The Task-8 shim built an
`epithet auth oidc …` command line that no longer exists. `pkg/broker` still
runs subprocess commands until Task 11 — bridge with a self-contained inline
command is no longer possible, so **Tasks 10 and 11 must be executed and
reviewed as a pair**: proceed to Task 11 before running the full integration
suite. Unit tests for `pkg/auth/oidc` and the rest of `make test` must still
pass; `test/sshd` remains skipped from Task 8 if it was.

- [ ] **Step 6: Run tests** — `go test ./pkg/auth/... ./pkg/... 2>&1 | tail -20` then `make build` — Expected: PASS/builds (integration pair-gated with Task 11).

- [ ] **Step 7: Checkpoint** — report; stop for review (reviewing 10+11 together is fine).

---

### Task 11: Broker in-process auth — `TokenFunc`, proactive refresh, match-path collapse

**Files:**
- Rewrite: `pkg/broker/auth.go`
- Modify: `pkg/broker/broker.go` (`New` signature; `MatchWithUserOutput`)
- Rewrite: `pkg/broker/auth_test.go`; delete `pkg/broker/auth_singleflight_test.go` (replace with in-process equivalents inside `auth_test.go`)
- Modify: `pkg/broker/broker_test.go`
- Modify: `cmd/epithet/agent.go` (wire the real OIDC TokenFunc)
- Modify: `go.mod` (`go mod tidy` drops `cbroglie/mustache`)

**Interfaces:**
- Produces (consumed by Tasks 12, 14):

```go
// pkg/broker/auth.go — final surface:

// TokenFunc acquires a fresh JWT. Invocations are serialized by Auth, so a
// stateful closure (holding oauth2 refresh state) needs no locking of its own.
type TokenFunc func(ctx context.Context, out io.Writer) (string, error)

type Auth struct { /* fetch TokenFunc; mu; token string; expiresAt time.Time; inflight *authFlight */ }

func NewAuth(fetch TokenFunc) *Auth

// Token returns a JWT valid for at least expiryBuffer, fetching/refreshing if
// needed. Concurrent callers share one in-flight fetch; joiners get a replay
// of its user-visible output so far.
func (a *Auth) Token(ctx context.Context, out io.Writer) (string, error)

// ForceRefresh discards the cached token and fetches a new one. 401 safety net.
func (a *Auth) ForceRefresh(ctx context.Context, out io.Writer) (string, error)

// parseJWTExpiry reads exp from an unverified JWT payload. Advisory only —
// the policy server does the real verification.
func parseJWTExpiry(token string) (time.Time, error)
```

- `broker.New(log slog.Logger, socketPath string, fetch TokenFunc, caClient *caclient.Client, agentSocketDir string, options ...Option) (*Broker, error)`
- The `authFlight` waiter/replay mechanism is **kept** (attach/detach/Write,
  waiter refcount canceling the fetch context when the last waiter leaves) —
  minus everything subprocess: no pipes, no process groups, no state blobs. The
  flight goroutine calls `a.fetch(flightCtx, flight)` instead of `execute`.

- [ ] **Step 1: Write the failing tests** (these replace the shell-script fixtures):

```go
// pkg/broker/auth_test.go — new content, representative tests:
package broker

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/stretchr/testify/require"
)

func mintValid(t *testing.T, idp *oidctest.IdP, d time.Duration) string {
	return idp.MintIDToken("t@example.com", time.Now().Add(d))
}

func TestTokenFetchesOnceWhileValid(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	a := NewAuth(func(ctx context.Context, out io.Writer) (string, error) {
		calls.Add(1)
		return mintValid(t, idp, time.Hour), nil
	})
	for range 5 {
		_, err := a.Token(context.Background(), nil)
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), calls.Load())
}

func TestTokenRefreshesProactivelyNearExpiry(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	a := NewAuth(func(ctx context.Context, out io.Writer) (string, error) {
		calls.Add(1)
		// Expires inside expiryBuffer: every call must refetch.
		return mintValid(t, idp, expiryBuffer/2), nil
	})
	_, err := a.Token(context.Background(), nil)
	require.NoError(t, err)
	_, err = a.Token(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load(), "near-expiry token must be refreshed, not reused")
}

func TestConcurrentTokenCallsShareOneFetch(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	release := make(chan struct{})
	a := NewAuth(func(ctx context.Context, out io.Writer) (string, error) {
		calls.Add(1)
		fmt.Fprint(out, "visit: https://example/auth\n")
		<-release
		return mintValid(t, idp, time.Hour), nil
	})

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.Token(context.Background(), io.Discard)
			require.NoError(t, err)
		}()
	}
	time.Sleep(100 * time.Millisecond) // Let everyone join the flight.
	close(release)
	wg.Wait()
	require.Equal(t, int32(1), calls.Load())
}

func TestForceRefreshDiscardsCachedToken(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	a := NewAuth(func(ctx context.Context, out io.Writer) (string, error) {
		calls.Add(1)
		return mintValid(t, idp, time.Hour), nil
	})
	_, _ = a.Token(context.Background(), nil)
	_, err := a.ForceRefresh(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load())
}

func TestParseJWTExpiry(t *testing.T) {
	idp := oidctest.New(t)
	exp := time.Now().Add(7 * time.Minute).Truncate(time.Second)
	got, err := parseJWTExpiry(idp.MintIDToken("x@y.z", exp))
	require.NoError(t, err)
	require.WithinDuration(t, exp, got, time.Second)

	_, err = parseJWTExpiry("not-a-jwt")
	require.Error(t, err)
}
```

Port the cancellation semantics tests from `auth_singleflight_test.go`
(`Run_CancelKillsCommandAndAllowsFreshAttempt`, `JoinerKeepsFlightAliveAfterLeaderCancels`)
to the in-process shape: the fetch func blocks on `<-ctx.Done()` /
`<-release`, callers cancel their contexts, assertions unchanged in spirit.
Also port the replay-to-joiner assertion (joiner's writer receives the already-
emitted "visit:" line).

- [ ] **Step 2: Run** `go test ./pkg/broker -run TestToken -v` — Expected: FAIL (old Auth API).

- [ ] **Step 3: Rewrite `pkg/broker/auth.go`.** Structure:

```go
func (a *Auth) Token(ctx context.Context, out io.Writer) (string, error) {
	a.mu.Lock()
	if a.token != "" && time.Now().Add(expiryBuffer).Before(a.expiresAt) {
		tok := a.token
		a.mu.Unlock()
		return tok, nil
	}
	a.mu.Unlock()
	return a.acquire(ctx, out)
}

// acquire joins or starts a flight (same attach/wait/replay dance as today,
// with runFlight calling a.fetch and then parseJWTExpiry to stamp expiresAt).
```

`ForceRefresh` zeroes `token`/`expiresAt` under the lock, then calls `acquire`.
`parseJWTExpiry`: split on `.`, `base64.RawURLEncoding.DecodeString` the middle
segment, unmarshal `struct{ Exp int64 \`json:"exp"\` }`, error on missing exp.
Delete: `MaxStateBlobSize`, `commandWaitDelay`, `execute`, mustache, `state`,
`ClearToken` (replaced by `ForceRefresh`), the `os/exec`/`syscall` imports.

- [ ] **Step 4: Collapse the match path.** In `broker.go`, `MatchWithUserOutput`
steps 5+ become:

```go
publicKey, privateKey, err := sshcert.GenerateKeys()
if err != nil {
	return b.deny(fmt.Errorf("failed to generate keypair: %w", err))
}

token, err := b.auth.Token(ctx, userOutput)
if err != nil {
	return b.deny(fmt.Errorf("authentication failed: %w", err))
}

certResp, err := b.caClient.GetCert(ctx, token, &caserver.CreateCertRequest{
	PublicKey: publicKey, Connection: conn,
})
var invalidToken *caclient.InvalidTokenError
if errors.As(err, &invalidToken) {
	// Safety net: server-side revocation or clock skew. One forced refresh.
	b.log.Warn("CA rejected token despite local validity, refreshing once")
	token, err = b.auth.ForceRefresh(ctx, userOutput)
	if err != nil {
		return b.deny(fmt.Errorf("re-authentication failed: %w", err))
	}
	certResp, err = b.caClient.GetCert(ctx, token, &caserver.CreateCertRequest{
		PublicKey: publicKey, Connection: conn,
	})
}
if err != nil {
	return b.deny(fmt.Errorf("certificate request failed: %w", err))
}
```

with `func (b *Broker) deny(err error) MatchResponse { b.log.Error("match failed", "error", err); return MatchResponse{Allow: false, Error: err.Error()} }`.
Delete `maxRetries`, the retry loop, and the five per-type `errors.As` branches
(the typed errors still exist in caclient for the breaker's success predicate).
Also delete the net/rpc-style `Broker.Match` method and `MatchRequest`
(`MatchResponse` stays — it is `MatchWithUserOutput`'s return type); update
`test/sshd/broker_test.go`'s call site when Task 14 rewires it.
`broker.New` takes `fetch TokenFunc` instead of `authCommand string`.
Note: `CreateCertRequest` literal uses the non-pointer fields from Task 8.

- [ ] **Step 5: Wire the real TokenFunc in `cmd/epithet/agent.go`** (replacing the Task-8 shim):

```go
discovery, err := caClient.GetDiscovery(context.Background())
if err != nil || discovery == nil || discovery.Auth == nil {
	return fmt.Errorf("failed to get discovery config from CA: %w", err)
}
oidcCfg := authoidc.Config{
	IssuerURL:    discovery.Auth.Issuer,
	ClientID:     discovery.Auth.ClientID,
	ClientSecret: discovery.Auth.ClientSecret,
	TLSConfig:    tlsCfg,
}
// Refresh state lives in this closure, in memory only. broker.Auth serializes
// invocations, so no locking is needed here.
var oauthState *oauth2.Token
tokenFn := func(ctx context.Context, out io.Writer) (string, error) {
	idToken, next, err := authoidc.Authenticate(ctx, oidcCfg, oauthState, out)
	if err != nil {
		return "", err
	}
	oauthState = next
	return idToken, nil
}
b, err := broker.New(*logger, brokerSock, tokenFn, caClient, agentDir)
```

(import `authoidc "github.com/epithet-ssh/epithet/pkg/auth/oidc"` and
`golang.org/x/oauth2`). Delete the `Auth` field from `AgentCLI` and the
`--auth`-vs-discovery branching.

- [ ] **Step 6: Run tests** — `make build && make test && go test -race ./pkg/broker` — Expected: PASS. Run `go mod tidy` and confirm `cbroglie/mustache` leaves `go.mod`.

- [ ] **Step 7: Checkpoint** — report (Tasks 10+11 reviewed together); stop.

---

### Task 11b: Per-connection certificates — delete the cert cache; narrow principals

Per spec §11. A vertical slice: evaluator, wire, caserver, caclient, broker, and
inspect change together so the tree stays green.

**Files:**
- Delete: `pkg/broker/certs.go`, `pkg/broker/certs_test.go`
- Modify: `pkg/policyserver/evaluator/evaluator.go` (+ its test)
- Modify: `pkg/wire/wire.go` (`PolicyResponse` loses `Policy`)
- Modify: `pkg/policy/policy.go` (delete `Policy` + `Matches`; keep `Connection`/`ConnectionHash`)
- Modify: `pkg/caserver/caserver.go` (`CreateCertResponse` loses `Policy`; audit logging keeps using the server-side `policyResp.CertParams`)
- Modify: `pkg/caclient/caclient.go` (`CertResponse` loses `Policy`)
- Modify: `pkg/broker/broker.go` (match path: agents fast path → mint → ensureAgent), `pkg/broker/grpc_server.go` + `cmd/epithet/inspect.go` (drop certificate-list display)

**Interfaces:**
- `wire.PolicyResponse` = `{CertParams CertParams}`.
- `caserver.CreateCertResponse` = `{Certificate sshcert.RawCertificate}`.
- Evaluator: certs carry **only the requested principal** —
  `CertParams.Names = []string{conn.RemoteUser}` when authorized. Delete
  `computeAuthorizedPrincipals`, `computeHostUsers`,
  `buildResponseWithHostUsers`'s hostUsers plumbing, and the
  `policy.Policy{HostUsers: ...}` construction. Authorization is the single-pass
  matched-rules check from Task 5: does any matching host rule (or defaults)
  allow `conn.RemoteUser` for one of the identity's tags?

- [ ] **Step 1: Write the failing evaluator test**

```go
func TestCertCarriesOnlyRequestedPrincipal(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{"alice@example.com": {"admin"}},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{"root": {"admin"}, "deploy": {"admin"}},
		},
		Hosts: map[string]*policyserver.Rules{"*.example.com": {}},
	}
	e := NewForTesting(cfg)
	resp, err := e.Evaluate(context.Background(), "alice@example.com",
		time.Now().Add(5*time.Minute),
		policy.Connection{RemoteHost: "web.example.com", RemoteUser: "root"})
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, resp.CertParams.Names,
		"cert must not carry the union of all authorized principals")
}
```

- [ ] **Step 2: Run** — Expected: FAIL (Names is the union today).
- [ ] **Step 3: Implement the evaluator narrowing** per the Interfaces block,
then delete `Policy` from `wire.PolicyResponse`, `CreateCertResponse`, and
`caclient.CertResponse`, and delete `policy.Policy`/`Matches`. In `broker.go`:
delete the `certStore` field, `NewCertificateStore`, the Step-3/4 lookup block
and the `certStore.Store` call — the match path after the agents fast path is
exactly: generate keypair → `b.auth.Token` → `GetCert` (with the single 401
retry from Task 11) → `ensureAgent`. Move the `expiryBuffer` constant from
`certs.go` into `broker.go` before deleting the file. Drop
`InspectResponse.Certificates`, its proto conversion, and the inspect display
block. Keep the `caserver` audit log intact — it reads the policy response
server-side and never depended on the client-bound field.
- [ ] **Step 4: Run tests** — `make build && make test && go test -race ./pkg/broker` — Expected: PASS (certs_test.go deleted with the store).
- [ ] **Step 5: Checkpoint** — report; stop for review.

---

### Task 12: Named profiles + Tag-gated ssh config generation

**Files:**
- Modify: `cmd/epithet/agent.go` (Name flag; rundir; `generateSSHConfig`; `checkSSHConfigInclude` ordering warning)
- Modify: `cmd/epithet/inspect.go` (derive rundir from `--name`, not CA-URL hash)
- Modify: `cmd/epithet/match.go` (`Broker` flag becomes `required:""`, drop the stale `~/.epithet/broker.sock` default)
- Test: `cmd/epithet/agent_test.go` (create if absent)

**Interfaces:**
- `AgentCLI` gains `Name string \`help:"Profile name; names the rundir and the ssh Tag (epithet-<name>)" default:"default"\``.
- Rundir: `~/.epithet/run/<name>` (replaces the CA-URL hash). Reject names not
  matching `^[a-zA-Z0-9_-]+$` (they land in paths and ssh config).
- Generated file (`<rundir>/ssh-config.conf`):

```
# Generated by epithet agent - do not edit manually
# Profile: <name>
#
# In ~/.ssh/config, tag the hosts this profile should handle, then include
# epithet's generated config AFTER the Tag lines (tags must be set before
# Match tagged is evaluated):
#
#   Host *.example.com
#       Tag epithet-<name>
#   Include ~/.epithet/run/*/ssh-config.conf
#
# Requires OpenSSH 9.4 or newer (Tag / Match tagged).

Match tagged epithet-<name> exec "<epithetPath> match --host '%h' --port '%p' --user '%r' --jump '%j' --hash '%C' --broker '<brokerSock>'"
    IdentityAgent <agentDir>/%C
```

- `checkSSHConfigInclude` additionally warns when the Include line appears
  before the first `Tag ` line in `~/.ssh/config` ("Include must come after Tag
  lines or epithet will never activate").

- [ ] **Step 1: Write failing tests**

```go
// cmd/epithet/agent_test.go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateSSHConfigIsTagGated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh-config.conf")
	a := &AgentCLI{Name: "work"}
	require.NoError(t, a.generateSSHConfig(path, "/run/agent", "/run/broker.sock", "/home/u"))

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, `Match tagged epithet-work exec`)
	require.Contains(t, s, "IdentityAgent /run/agent/%C")
	require.Contains(t, s, "--broker '/run/broker.sock'")
	require.NotContains(t, strings.Split(s, "Match tagged")[0], "\nMatch ",
		"nothing before the tagged Match may open a match block")
}

func TestProfileNameValidation(t *testing.T) {
	require.Error(t, validateProfileName("has space"))
	require.Error(t, validateProfileName("has/slash"))
	require.NoError(t, validateProfileName("home-2"))
}
```

- [ ] **Step 2: Run** `go test ./cmd/epithet -run 'SSHConfig|ProfileName' -v` — Expected: FAIL.

- [ ] **Step 3: Implement** per the interface block: `validateProfileName` with the
regexp; rundir `filepath.Join(homeDir, ".epithet", "run", a.Name)` in
`AgentStartCLI.Run` (delete `hashString`/`instanceID` there); the new template in
`generateSSHConfig` (signature gains nothing — it reads `a.Name`); the ordering
warning in `checkSSHConfigInclude` (track the line numbers of the first `Tag `
occurrence and the epithet `Include`; warn if include < tag). In `inspect.go`,
replace the `hashString(fmt.Sprintf("%v", parent.CaURL))` derivation with the
profile name (inspect inherits `parent.Name`). In `match.go`, `Broker` becomes
`required:""` (generated config always passes it).

- [ ] **Step 3b: Delete the rundir lifecycle machinery** (spec §13): with a
named, stable rundir the agent owns its directory — `MkdirAll` +
truncate-and-rewrite of the socket and config at startup replaces GC. Delete
`cleanupStaleRunDirs` (`agent.go:287-344`), the PID-file write (`:87-91`), the
`Signal(0)` liveness probe, and the `defer os.RemoveAll(tempDir)` (leaving the
generated config in place is harmless and inspectable; the socket is removed and
recreated by `startBrokerListener`). A stale profile's dead socket is benign:
`epithet match` exits non-zero and ssh falls back.

- [ ] **Step 4: Run tests** — `make build && make test` — Expected: PASS.

- [ ] **Step 5: Checkpoint** — report; stop for review.

---

### Task 12b: Broker IPC — newline-framed JSON replaces gRPC

Per spec §8. Both peers are the same binary; the socket is 0700 in the profile
rundir; the exec line is regenerated every agent start. No compatibility
contract exists, so this is a clean swap.

**Files:**
- Create: `pkg/broker/protocol.go` (request/event types + server loop)
- Delete: `pkg/broker/grpc_server.go`, `pkg/brokerv1/` (whole dir), `proto/` (whole dir), `buf.yaml`, `buf.gen.yaml`
- Modify: `pkg/broker/broker.go` (`serve()` uses the JSON server; delete grpc imports)
- Modify: `cmd/epithet/match.go`, `cmd/epithet/inspect.go` (JSON client)
- Modify: `Makefile` (delete the `generate` target), `AGENTS.md` (drop the buf/generated-files rules — flag this edit to Brian at checkpoint since it is agent instructions)
- Test: `pkg/broker/protocol_test.go`
- Modify: `go.mod` (`go mod tidy` drops `grpc` and `protobuf`)

**Interfaces:**

```go
// pkg/broker/protocol.go — the whole wire contract:

// Request is one line of JSON from the client. Exactly one field is set.
type Request struct {
	Match   *policy.Connection `json:"match,omitempty"`
	Inspect *struct{}          `json:"inspect,omitempty"`
}

// Event is one line of JSON from the broker. For match: zero or more Output
// events then exactly one Result. For inspect: exactly one Inspect event.
type Event struct {
	Output  string           `json:"output,omitempty"`
	Result  *MatchResponse   `json:"result,omitempty"`
	Inspect *InspectResponse `json:"inspect,omitempty"`
}

// Serve accepts connections on l and handles one Request per connection.
func (b *Broker) serveProtocol(ctx context.Context, l net.Listener)
```

Client side (`match.go`): `net.Dial("unix", brokerSock)`, write the request line,
`bufio.Scanner` over response lines (`scanner.Buffer` sized to 1 MiB for large
inspect payloads), print `Output` to stderr as it arrives, act on `Result`
exactly as today (`error` is a message; `!allow` → exit 1). `InspectResponse`
marshals directly for `--json` — the triple representation is gone.

- [ ] **Step 1: Write failing protocol tests**

```go
// pkg/broker/protocol_test.go
func TestMatchStreamsOutputThenResult(t *testing.T) {
	b := newTestBroker(t, func(ctx context.Context, out io.Writer) (string, error) {
		fmt.Fprintln(out, "visit: https://example/auth")
		return mintValid(t, testIdP(t), time.Hour), nil
	}) // reuse Task 11's broker test fixtures; CA stubbed as in broker_test.go
	client := dialBroker(t, b) // net.Dial + helper

	require.NoError(t, json.NewEncoder(client).Encode(Request{Match: &policy.Connection{
		RemoteHost: "h", RemoteUser: "u", Hash: "abc",
	}}))

	var sawOutput bool
	sc := bufio.NewScanner(client)
	for sc.Scan() {
		var ev Event
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
		if ev.Output != "" {
			sawOutput = true
		}
		if ev.Result != nil {
			require.True(t, sawOutput, "output must precede result")
			return
		}
	}
	t.Fatal("no result event received")
}

func TestMalformedRequestGetsErrorResult(t *testing.T) {
	b := newTestBroker(t, nil)
	client := dialBroker(t, b)
	fmt.Fprintln(client, "{not json")
	sc := bufio.NewScanner(client)
	require.True(t, sc.Scan())
	var ev Event
	require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
	require.NotNil(t, ev.Result)
	require.False(t, ev.Result.Allow)
	require.NotEmpty(t, ev.Result.Error)
}
```

- [ ] **Step 2: Run** — Expected: FAIL (types undefined).
- [ ] **Step 3: Implement the server.** `serveProtocol` accepts, reads one line
(`bufio.Reader.ReadBytes('\n')`, cap the line at `wire.MaxBodySize`), dispatches:
`Match` → `MatchWithUserOutput(connCtx, *req.Match, eventWriter)` where
`eventWriter`'s `Write` emits `Event{Output: string(p)}` lines (guard concurrent
writes with a mutex — auth output and the result must not interleave mid-line);
then the terminal `Event{Result: &resp}`. Connection close cancels `connCtx`
(preserving today's "ssh gave up → abandon the match" semantics: wrap the conn
read side — when the peer closes, cancel). `Inspect` → `Event{Inspect: ...}`.
Replace `broker.serve()`'s grpc server with `serveProtocol`; delete
`grpc_server.go`.
- [ ] **Step 4: Rewrite the clients** (`match.go`, `inspect.go`) per the
Interfaces block; delete the proto→JSON converters in `inspect.go`.
- [ ] **Step 5: Delete** `pkg/brokerv1/`, `proto/`, `buf.yaml`, `buf.gen.yaml`,
the `generate` Makefile target; `go mod tidy` (grpc + protobuf leave, and with
them the otel/genproto indirects). Update `AGENTS.md`'s "Regenerate protobufs"
paragraph — flag at checkpoint.
- [ ] **Step 6: Run tests** — `make build && make test && go test -race ./pkg/broker` — Expected: PASS, including the ported user-output streaming test (`Test_MatchStreamsUserOutput` semantics move here from broker_test.go).
- [ ] **Step 7: Checkpoint** — report; stop for review.

---

### Task 13: Raise and unify body limits

**Files:**
- Modify: `pkg/caserver/caserver.go`, `pkg/policyserver/policyserver.go`, `pkg/ca/ca.go`
- Test: `pkg/policyserver/policyserver_test.go`, `pkg/caserver/caserver_test.go`

**Interfaces:**
- One shared constant in `pkg/wire`: `const MaxBodySize = 64 * 1024` — request
  bodies and trusted-peer response bodies alike. Rationale comment: real ID
  tokens with group claims run 4-8 KiB; 64 KiB leaves an order of magnitude.
- Truncation must report "too large", not a JSON parse error: read with
  `io.LimitReader(r.Body, wire.MaxBodySize+1)` and error when
  `len(body) > wire.MaxBodySize`.

- [ ] **Step 1: Write the failing test**

```go
// pkg/policyserver/policyserver_test.go — add:
func TestOversizedRequestReportsTooLarge(t *testing.T) {
	h := newTestHandler(t) // whatever helper Task 4/7 left in place
	big := bytes.Repeat([]byte("a"), wire.MaxBodySize+1)
	req := signedRequest(t, "POST", "/", big) // service-signed per Task 7 helpers
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.Contains(t, rec.Body.String(), "too large")
}
```

- [ ] **Step 2: Run** — Expected: FAIL (silently truncates → 400 "Invalid JSON").

- [ ] **Step 3: Implement** the limit+1 pattern at all four sites: policyserver
`ServeHTTP` body read, caserver `createCert` (replace `RequestBodySizeLimit`),
and the two `ca.go` response reads (`FetchDiscovery`, `RequestPolicy`) — for
responses, the error is `fmt.Errorf("policy server response exceeds %d bytes", wire.MaxBodySize)`.
Delete `RequestBodySizeLimit` and `Config.MaxRequestSize` (one constant now).

- [ ] **Step 4: Run tests** — `make test` — Expected: PASS.

- [ ] **Step 5: Checkpoint** — report; stop for review.

---

### Task 14: Integration tests — sshd end-to-end, server, policy

**Files:**
- Modify: `test/sshd/broker_test.go`
- Modify: `test/server/server_test.go`
- Modify: `test/policy/integration_test.go`

**Interfaces:**
- Consumes: everything. This task proves the whole pipeline.

- [ ] **Step 1: Rewrite `test/sshd/broker_test.go`.**
  - Replace the shell-script auth plugin (`writeTestScript`, the netstring token)
    with `oidctest.New(t)` + an injected `broker.TokenFunc` that returns
    `idp.MintIDToken("test@example.com", time.Now().Add(5*time.Minute))`.
  - Replace the stub policy server (which returned `"type": "command"`) with the
    **real** `policyserver.NewHandler` wired to a real `oidc.Validator` (against
    the fake IdP) and a real evaluator whose config authorizes
    `test@example.com` on the test host — service-signed by a real `ca.CA`.
    This makes sshd the full-stack test: broker → CA → policy → JWKS.
  - Call sites: `broker.New(logger, sock, tokenFn, caClient, agentDir)`; the old
    `b.Match(MatchRequest{...}, &resp)` call becomes
    `b.MatchWithUserOutput(context.Background(), conn, nil)`.
  - Add the **tag-gating** end-to-end case: write a client ssh config

```
Host tagged.test
    Tag epithet-test
Host *
    # deliberately untagged
Include <rundir>/ssh-config.conf
```

    plus `Match tagged`-generated config from Task 12, and assert (a) ssh to the
    tagged host authenticates via cert, (b) ssh to an untagged host never
    invokes `epithet match` (e.g. point `--broker` at a socket that fails the
    test if dialed — a `net.Listener` that calls `t.Error` on accept).
    Gate this case on the installed ssh supporting tags:
    `ssh -V` ≥ 9.4, else `t.Skip("OpenSSH 9.4+ required for Tag")`.
- [ ] **Step 2: Rewrite `test/server/server_test.go`.** Replace the hand-rolled
mock IdP (`/.well-known/openid-configuration` + empty JWKS, lines ~26-48) with
`oidctest.New(t)`. Discovery assertions change to the slim anonymous shape:
`GET /discovery` with no auth returns `{"auth":{"issuer":...,"client_id":...}}`
and never `matchPatterns`.
- [ ] **Step 3: Rewrite `test/policy/integration_test.go`.** The "requires a
running OIDC provider" skips (lines ~54-56, ~131) die: use `oidctest`, mint real
tokens, exercise the real validation path — valid token → 200 with certParams
(assert `notAfter` equals the token expiry), expired token → 401, wrong audience
→ 401, unknown user → 403.
- [ ] **Step 4: Add the deletion-risk coverage** (spec §10): in `test/sshd` or
`pkg/broker/broker_test.go` as fits: (a) **fan-out** — match three distinct
hosts sharing one policy; assert three certs are minted (three CA hits — count
requests in the stub/real CA handler) and each cert's principals equal exactly
the requested user; (b) **CA down** — point the broker at a closed port; assert
the match result is `Allow: false` with a non-empty, human-legible error
mentioning the CA (this is the error text users actually see via ssh).
- [ ] **Step 5: Run** — `make test` (integration tests included) — Expected: PASS, no skips other than the OpenSSH-version gate.
- [ ] **Step 6: Checkpoint** — report; stop for review.

---

### Task 15: Dead code and small-wins sweep

Every item verified-dead by the design exploration, plus the spec §13 folded-in
simplifications. For each group: change, then `make build && make test` before
moving to the next.

**Files & items:**

- [ ] **Step 1: `pkg/ca`/`pkg/caserver`:** `ca.AuthToken` (`ca.go:357-363`),
`ca.WithHTTPClient` (`ca.go:131-137`), `caServer.httpClient` (field, `New` param —
update `New(c, log, certLogger)` call sites in `cmd/epithet/ca.go` and tests),
`MultiCertLogger` + `certEventForJSON` + `CertEvent.toJSON`
(`caserver/logger.go` — keep `CertLogger`, `NoopCertLogger`, and the slog logger
that production uses), `parseCert`/`generateFingerprint`/`sha256Sum` replaced by
`sshcert.Parse` + one fingerprint helper if trivially reachable — otherwise leave
(spec lists the dedup as follow-up; only delete if unreferenced).
- [ ] **Step 2: `pkg/policyserver`:** `ErrUnauthorized`/`ErrForbidden`/
`ErrNotHandled` vars, `Unauthorized()`/`NotHandled()` constructors (keep
`Forbidden`/`InternalError` — they are live in the evaluator),
`pkg/policyserver/discovery.go` (tombstone file) and `discovery_test.go` if it
only tests the tombstone, `PolicyRulesConfig.BootstrapAuth` if not already gone
(Task 8), `TestURLStuff` (`caserver_test.go:21-31`).
- [ ] **Step 3: `pkg/broker`/`pkg/agent` — read-only one-credential agent
(spec §13):** delete `Broker.BrokerSocketPath`, `Broker.LookupCertificate`,
`Broker.StoreCertificate` (if not already gone with 11b), `agent.IsAgentStopped`
+ `errAgentStopped`. Rewrite `pkg/agent/agent.go`: drop the generated keypair
and the `caClient` field/parameter — `agent.New(logger *slog.Logger, socketPath string) *Agent`
(no error) — and replace the mutable `agent.NewKeyring()` with a read-only
wrapper implementing `agent.ExtendedAgent`: `List` and `Sign`/`SignWithFlags`
delegate to an atomically-swapped inner keyring; `Add`/`Remove`/`RemoveAll`/
`Lock`/`Unlock` return `fmt.Errorf("epithet agent is read-only")`.
`UseCredential` builds a fresh keyring, adds the one credential, and swaps it in
(`atomic.Pointer` or mutex) — the list-add-remove-old dance and its three
`Close()`-on-error paths go away. Update the call site (`broker.go` ensureAgent)
and agent tests; add a test asserting `Add` from a client connection is refused.
- [ ] **Step 4: `pkg/caclient`/`pkg/breakerpool`:** anything Task 9 left:
`WithHTTPClient` if still present; `breakerpool` test-only exports
(`AllUnavailable`, `Len`, `Entry.Settings`) — delete only if their *only*
callers are their own package tests asserting them; keep what breakerpool's own
unit tests legitimately exercise.
- [ ] **Step 5: `cmd/epithet`:** `var _ *ssh.Certificate` (`inspect.go:299`),
`configFilePaths` double-glob (leave the function; it is used by `policy.go` —
just delete it if Tasks 8/8b removed the last caller), the binary-name command
inference (`main.go:52-58` — `epithet-linux-amd64 agent` mis-parses; nothing in
contrib/goreleaser uses hyphenated invocation).
- [ ] **Step 6: Dependency swaps (spec §13):**
  - `doublestar` → stdlib `path.Match` in
    `pkg/policyserver/evaluator/evaluator.go` (hostname globs only; `path.Match`
    is behaviourally equivalent for `*.example.com` patterns — add an evaluator
    test pinning `*.example.com` matches `a.example.com` but not
    `a.b.example.com`, documenting the single-label semantics).
  - `mikesmitty/edkey` → `ssh.MarshalPrivateKey` in `pkg/sshcert/cert.go`
    (`GenerateKeys` keeps its signature; round-trip test: generated key parses
    with `ssh.ParsePrivateKey`).
  - `go-chi/chi` → `http.NewServeMux` in `cmd/epithet/ca.go` and
    `cmd/epithet/policy.go`; replace `listen.go`'s bare
    `http.ListenAndServe`/`http.Serve` with a configured `http.Server`
    (`ReadHeaderTimeout: 10s`, `ReadTimeout: 30s`, `WriteTimeout: 30s`,
    `IdleTimeout: 60s`) — the internet-facing CA currently has no slowloris
    protection. Request logging, if kept, is a ~10-line handler wrapper.
  - Unify the four timeout constants (`tlsconfig.DefaultTimeout`,
    `caclient.DefaultTimeout`, and the hardcoded `30 * time.Second` in
    `ca.go`/`caserver.go`) on one shared constant.
  - Drop `Connection.LocalHost` (transmitted, never read anywhere) and the
    `os.Hostname()` call in `match.go`; `Port`/`ProxyJump` stay for the audit
    log.
  - `go mod tidy`; confirm `doublestar`, `edkey`, `chi`, `gotest.tools` are gone
    from `go.mod`.
- [ ] **Step 7: Run** — `make build && make test` — Expected: PASS.
- [ ] **Step 8: Checkpoint** — report; stop for review.

---

### Task 16: Docs, examples, and yatl bookkeeping

- [ ] **Step 1: Rewrite `docs/authentication.md`** as the OIDC document: the JWT
contract (§1 of the spec), in-process flow, proactive refresh, the fixed scopes,
memory-only refresh state, and the 401 safety net. Delete the plugin protocol
spec, the Bash and Python plugin examples, and all fd-3/fd-4 references.
- [ ] **Step 2: Update the other docs.**
  - `README.md`: drop "custom auth plugin" (`:37`, `:56`, `:62`); add the
    Tag-based ssh config snippet and the OpenSSH 9.4 floor.
  - `docs/architecture.md`: replace the auth-plugin sections (`:155-167`,
    `:181-198`, `:318-329`) with in-process OIDC; note the CA↔policy service JWT.
  - `docs/oidc-setup.md`: remove "test the auth plugin directly" (`:280-290`);
    describe `Tag`/`Include` setup.
  - `docs/policy-server.md` + `docs/policy-server-api.yaml`: token is a bare
    JWT; auth is the `Authorization: Bearer <service JWT>` scheme (document the
    claims incl. `bh`); `certParams` gains `notAfter` (RFC 3339) and
    `expiration` documented as integer nanoseconds (or switch the wire field to
    a string — decide with Brian at review; default: document reality);
    document `GET /` discovery shape `{"auth":{...}}`; delete `hostPattern` and
    `matchPatterns` references.
  - Delete `docs/design-discovery-protocol.md` — it documents the Link-header/
    authenticated-patterns/RFC 9421 protocol this effort replaces; leaving it
    creates a second, contradictory source of truth.
  - Purge the "host patterns are obtained dynamically from CA discovery" claims
    from `docs/architecture.md` (lines ~9, 48, 127-133, 161-162, 177, 187,
    213-215, 291-293) and `contrib/macos/README.md`; document the JSON broker
    protocol where architecture.md described gRPC.
- [ ] **Step 3: Clean examples.** Delete `examples/bash_auth_example.bash` and
`examples/client/.epithet/test-auth-plugin.sh`; update `examples/README.md`,
`examples/epithet.config.example` (drop `agent.auth`, add `agent.name`), and
`examples/client/.epithet/config.yaml`.
- [ ] **Step 4: yatl bookkeeping.**

```bash
yatl close t761tcz9 --reason "sh -c auth plugin execution removed; vector no longer exists (OIDC in-process)"
yatl close 1g8ka9wq --reason "client_id now required; audience check can no longer be skipped"
yatl close mrrf0wa8 --reason "mustache templating removed with subprocess auth"
yatl close 6jm8vvtv --reason "auth plugins removed; no plugin env contract to extend"
yatl close 0wxy5vnz --reason "already done; no CUE dependency remains in the tree"
yatl close 4pytxtsz --reason "moot: Hello already used breakerpool, and Hello is now deleted"
yatl new "Re-evaluate breakerpool: failover must live somewhere and a smart client is the easy path if designed in from the start. Fix or fold in: double-request-after-trip bug (single CA + ConsecutiveFailures>=1 => the all-breakers-open bypass re-issues the request; a slow-but-successful CA mints two certs per ssh connection)"
yatl new "epithet-aws: rework for --policy-source removal — launcher fetches AppConfig doc to a local file at container start and restarts the policy server on config version change"
yatl new "Policy server config parsing rework (direction recorded in ideas/oidc-only-auth.md §7)"
yatl new "Decide fate of combined 'epithet server' mode (likely delete; keep CA/policy process boundary). Blocks FreeBSD packaging task y4fsaskj, which assumes epithet server"
yatl new "Agent socket: split Listen() from Serve() so match can't return before the socket exists"
yatl new "Broker.Inspect: snapshot agents map under lock instead of holding the lock through the response build"
yatl new "sshcert.Parse wraps nil error; caserver duplicates sshcert.Parse+fingerprinting"
yatl new "tlsconfig.ValidateURL case-sensitive scheme check; unify with caclient validateCAURL"
yatl new "Restate or close gszy91dg (tunnel auth to remote agent) against in-process OIDC design"
yatl new "hv3622e5: consider dropping client_secret entirely (pure PKCE); BootstrapAuth would shrink to {issuer, client_id}"
```

- [ ] **Step 5: Run** — `make build && make test` — Expected: PASS.
- [ ] **Step 6: Final checkpoint** — full-repo review: `jj diff --stat`; verify
`go.mod` no longer lists `cbroglie/mustache`, `yaronf/httpsign`,
`gregjones/httpcache`, `bmatcuk/doublestar`, `mikesmitty/edkey`,
`go-chi/chi`, `gotest.tools`, `google.golang.org/grpc`, or
`google.golang.org/protobuf` (direct deps should be roughly 9; `gobreaker`
stays — breakerpool was deliberately kept); and
`grep -rn "auth plugin\|fd 3\|fd 4\|base64\|matchPatterns\|grpc" docs/ pkg/ cmd/ --include='*.go' --include='*.md'`
returns nothing stale. Report; stop.

---

## Self-review notes (kept for the executor)

- Tasks 8→11 deliberately pass through an intermediate state where the broker
  still shells out; Tasks 10 and 11 are a review pair. `test/sshd` may carry a
  documented `t.Skip` between Tasks 8 and 14 — it must be gone by Task 14.
- Type-consistency anchors: `wire.CertParams.NotAfter` (Tasks 6, 14),
  `oidc.Claims{Identity, ExpiresAt}` (Tasks 4, 6, 8),
  `broker.TokenFunc(ctx, out) (string, error)` (Tasks 11, 12, 14),
  `caclient.GetDiscovery(ctx) (*wire.Discovery, error)` (Tasks 9, 11, 14),
  `serviceauth.Authorize(req, body)` / `Verify(header, body)` (Tasks 7, 13, 14),
  `oidc.Authenticate(ctx, cfg, prev, out)` (Tasks 10, 11).
- Spec sections → tasks: §1→3, §2→10+11, §3→11, §4→8+9+12, §5→4+5+6, §6→7,
  §7→2+8+13 (config parsing rework deliberately absent — separate change),
  §8 (JSON IPC)→12b, §9 (docs)→16, §10→1+14, §11 (per-connection certs)→11b,
  §12 (dynamic policy deletion)→8b, §13 (folded-in smaller wins)→12 Step 3b + 15,
  dead-code inventory→15, yatl→16.
- Additional anchors from the second assumption round:
  `wire.PolicyResponse{CertParams}` and `CreateCertResponse{Certificate}`
  (Tasks 11b, 14), `broker.Request`/`broker.Event` JSON protocol (Tasks 12b, 14),
  `evaluator.New(ctx, serverCfg, policyCfg, tlsCfg)` (Tasks 8b, 14). Task 12b
  runs after 11b so the protocol never serializes the deleted certificate-list
  inspect data.
