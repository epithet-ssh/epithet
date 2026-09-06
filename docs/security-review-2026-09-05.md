# Security review — 2026-09-05

Reviewed implementation: `9e53288f` (`fix: honor policy principal mode in combined server`). Review task: `9af2fswp`. The findings and original validation below describe that baseline. Subsequent remediation status is recorded separately here.

**SR-01 remediation:** authentication now requires a nonempty OIDC subject from the configured, verified issuer. Static inventory requires a unique `oidc-subject` for every user; email never selects the user. Writ and certificate/audit identity retain the administrator-controlled `userName`. The former SR-01 probe is now an ordinary regression in `test/security/identity_test.go`, covering denied email impersonation (including verified email), denied userName fallback, and successful issuance for the bound subject after email changes. The migration is intentionally breaking; see [migration instructions](policy-server.md#migrating-from-email-lookup). SR-02 and SR-03 remain open.

**Release recommendation:** deploy the SR-01 subject-binding migration and fix SR-02 before a general release, and fix SR-03 before presenting custom host-enrollment paths as safely validated. Also resolve the existing default-principal decision (`fcaxpp6h`). The findings have concrete prerequisites; none establishes that a deployed server has been compromised.

| Finding | Severity | Evidence | Task |
| --- | --- | --- | --- |
| SR-01: unverified email becomes an authorization identity | High, provider-dependent | Full local OIDC → policy → CA issuance reproduction | `sf9zabf2` |
| SR-02: redirects bypass transport restrictions | Medium; potentially high impact during CA bootstrap | Client bearer, policy request body, and root-key retrieval reproduced | `767qfv72` |
| SR-03: ownership validation and persisted sshd paths differ | Medium, nondefault path/local attacker prerequisite | Ownership gate, configuration rendering, and symlink replacement reproduced | `9zekr2kf` |

## SR-01 — Unverified email can obtain another inventory user's certificate

**Location:** `pkg/policyserver/oidc/validator.go:88`, propagated through `pkg/policyserver/policyserver.go:150` and `pkg/policyserver/writpolicy/evaluator.go:100`.

After verifying the token signature, issuer, audience, and expiration, the validator takes any string `email` as the inventory identity. It never checks `email_verified`. The authenticated subject is discarded when email is present.

**Attack prerequisite:** the configured, trusted IdP must issue a token for the Epithet audience in which an attacker can claim an inventory user's email without proving ownership. An attacker does not get to choose an arbitrary issuer or forge its signature. Providers that enforce the required email ownership and uniqueness prevent this particular route. This review did not test Google accounts or establish that the user's Google deployment satisfies the prerequisite.

**Reproduction:** a local TLS IdP signed a token with `sub=attacker-subject`, `email=victim@example.com`, and `email_verified=false`. Real OIDC verification, the real service-authenticated CA/policy exchange, static inventory, Writ, and CA signing issued a certificate for the attacker's key with the victim's audit identity and the destination-bound root principal. The certificate passed `ssh.CertChecker.CheckCert`. Omitting `email_verified` had the same result. A control token using the attacker's own email was denied by policy.

This is an identity-binding failure, so hashed principals do not prevent it: the attacker acquires the correct hashed principal for the victim's authorized destination.

**Remediation implemented:** resolve the verified subject under the single configured issuer through an explicit inventory `oidc-subject`, with no email/userName fallback. Missing subjects fail authentication; missing or duplicate inventory bindings fail configuration loading. Unknown subjects are denied even when their token claims a known user's verified email. The bound subject still authenticates after email changes; Writ sees the administrator-controlled inventory `userName`, groups, and attributes. This closes the email-verification and reassignment routes without requiring SCIM or dynamic inventory.

OIDC distinguishes verified email ownership from stable identity and guarantees stability only for issuer plus subject. See [standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) and [claim stability](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).

## SR-02 — HTTPS redirects can leak credentials and downgrade bootstrap trust

**Location:** `pkg/tlsconfig/tlsconfig.go:61`, `pkg/caclient/caclient.go:482`, `pkg/caclient/caclient.go:269`, and `pkg/ca/ca.go` outbound requests. Default CA/client constructors also use HTTP clients without a redirect restriction.

The initial CLI URL check does not constrain subsequent redirect destinations. The shared HTTP client follows redirects, including HTTPS to HTTP. A redirect can expose credentials before any response validation occurs.

**Reproduction:** with TLS verification enabled and a trusted local TLS certificate:

- A CA endpoint returned HTTP 307 to a plaintext endpoint on the same hostname. The client sent its bearer token to that HTTP endpoint.
- `GetRoot` followed the same redirect and accepted the SSH CA public key returned over HTTP. Host enrollment consumes this result without rejecting the final plaintext URL.
- A policy endpoint returned HTTP 307 to a plaintext endpoint. The CA resent the original OIDC token in the POST body. Stripping an Authorization header would not protect that body.

**Attack prerequisite:** the legitimately contacted HTTPS endpoint, proxy, or redirect functionality must send an unsafe redirect. A passive network attacker cannot manufacture the initial redirect through correctly verified TLS. Once the client follows a plaintext hop, interception can disclose a token or substitute the initial CA trust key. A stolen OIDC bearer can request certificates for another key until token expiry, within that identity's policy permissions. Existing enrollment refuses an unexpected replacement key, so initial enrollment is the most consequential bootstrap case.

**Remediation:** define redirect rules per endpoint. Reject TLS downgrades and unexpected origin changes for credential-bearing requests; rejecting all redirects for certificate POSTs and service RPC is a simple option. Give anonymous bootstrap an explicit trust rule. Apply transport requirements to discovered OIDC endpoints too, while allowing legitimate separately advertised HTTPS endpoints. Cover library defaults, preserve explicit Unix-socket transport, and parse URL schemes rather than relying on a case-sensitive prefix check.

The proof covers HTTPS-to-HTTP behavior. Cross-origin HTTPS credential forwarding and OIDC endpoint downgrade paths require their own regression cases when implementing the fix.

## SR-03 — A user-replaceable symlink passes host enrollment's ownership check

**Location:** `cmd/epithet/host_sshd_access_unix.go:14` and `cmd/epithet/host_sshd.go:311`.

The access validator resolves domain and CA-key symlinks and checks that the resolved files and ancestors are root-controlled. Configuration rendering then uses the original paths. A path in a user's writable directory can point at a root-controlled file during validation and be replaced afterward. The emitted `TrustedUserCAKeys` directive still follows that replaceable path.

**Attack prerequisite:** an administrator must enroll using such a nondefault path, and a local attacker must control a symlink or directory component along that original path. The default root-controlled layout is not shown vulnerable. Given this configuration, replacement of the CA trust path could allow attacker-signed certificates for accounts otherwise permitted by sshd. OpenSSH's trusted-CA path is read during certificate authorization; see its [trusted CA authorization implementation](https://github.com/openssh/openssh-portable/blob/master/auth2-pubkey.c).

**Reproduction boundary:** the unprivileged probe uses an existing root-owned system file as an ownership fixture, confirms the gate succeeds, confirms rendering retains the original link, and replaces the link successfully. It does not claim that fixture is a valid enrolled domain/key, run privileged enrollment, or demonstrate a privileged SSH login. The configuration-to-trust impact follows from the inspected call path.

**Remediation:** persist the same safe canonical paths that are validated, and verify that every path component retained in configuration cannot be replaced by an unprivileged user. Audit domain, helper executable, CA key, and custom sshd configuration/fragment paths together. Preserve legitimate root-controlled system symlinks, including macOS layouts.

## Existing boundaries and remaining decisions

- **Default principal mode remains a release decision.** Account-name certificates are usable for that account on other hosts trusting the same CA and accepting that principal. Host-specific Writ checks at issuance cannot prevent reuse elsewhere. This is intentional compatibility behavior, already tracked in `fcaxpp6h`, not a newly discovered implementation bug. Destination-bound mode requires correct host-side configuration; sharing a domain intentionally shares the authorization boundary. Cloned generated domains deserve operational care.
- **`until` controls issuance matching.** Current Writ documentation says the rule stops matching at that instant. It does not cap a previously issued certificate at that instant. Similarly, disabling a static inventory user takes effect after restart for new decisions; existing certificates and SSH sessions are not revoked. Do not describe these controls as immediate session termination. This review does not classify the documented `until` semantics as a compiler defect.
- **CA parameter validation merits hardening.** `SignPublicKey` trusts policy-supplied principal lists and duration. The CLI accepts negative default durations, and the signer casts Unix expiration to an unsigned certificate timestamp. Reject nonpositive durations, invalid validity intervals, and empty principal sets before signing. No untrusted-client path to control these policy parameters, or OpenSSH login exploiting malformed validity, was demonstrated here.
- **Service request replay is bounded, not eliminated.** The verifier binds signature algorithm, audience, freshness, body hash, method, and host/path. It does not consume `jti`, and query strings are not bound. Current handlers do not use query parameters for authorization. Replaying a captured request does not allow changing its body or connection. The old `kwxdbey2` task contains obsolete `httpsig` details and should be reconciled with the current JWT implementation before further work.
- **The local broker assumes the user's OS account is trusted.** Private run directories and read-only SSH agents are meaningful defenses. Arbitrary connection hashes reach socket-path construction, and same-user clients can interfere with broker operation; this review did not establish an additional cross-user boundary bypass under the default private directory layout. Existing directories and socket ownership deserve explicit validation if shared/custom run directories are supported.
- **Availability remains partly a deployment responsibility.** Bodies and outbound waits are bounded, but this was not a load test or resource-exhaustion audit. Do not infer public-endpoint capacity or rate-limit protection from the functional tests.

The parameter, broker, and dependency hardening follow-ups are recorded in the existing `gfym5rbt` backlog. The inventory-service split, dynamic enrollment approval, direct inventory OIDC/RBAC, SCIM, and the planned CA-originated inventory lookup are future architecture. They are not credited as current defenses or reported as missing implemented checks.

## Validation and scope

Completed locally on macOS with Go `go1.27.1`:

- `make build` completed; because its file target reported nothing to build, `go build ./cmd/epithet` was also run successfully.
- `make test` passed, including the repository's policy/server/sshd integration tests.
- `go test -race ./pkg/broker` passed.
- The four opt-in review probes passed, meaning they reproduced the unsafe behavior described above.
- `govulncheck -show verbose ./...` reported zero reachable known vulnerabilities. It flagged two imported-package SSH advisories, `GO-2026-6354` and `GO-2026-6355`, fixed in `golang.org/x/crypto v0.56.0`; this checkout uses `v0.55.0`. It also flagged the unmaintained OpenPGP module component (`GO-2026-5932`), which this code does not call. These are scanner results, not demonstrated reachable exploits in Epithet. Recheck when updating dependencies and when building with a different Go version.

Initial socket-based test runs hit sandbox restrictions; the successful runs above used permission to create local listeners. All attack fixtures use disposable keys/tokens and local test servers. No deployed service, real IdP account, or system sshd configuration was modified.

Reproduce the findings:

```sh
GOCACHE=/tmp/epithet-go-build-cache go test -tags securityreview -v ./test/security
GOCACHE=/tmp/epithet-go-build-cache go test -tags securityreview -run TestReviewEnrollment -v ./cmd/epithet
```

The `securityreview` tag deliberately excludes the remaining vulnerability probes from the normal test suite. SR-01 has been replaced by `TestSubjectBindingControlsCertificateIssuance`, which runs in normal `make test` and requires safe behavior with positive controls. Other fixes should likewise replace their probes with ordinary regressions.

This was a source review plus focused local testing, not an exhaustive audit or a guarantee of security. It did not include sustained fuzzing, Internet-facing load tests, third-party IdP penetration testing, a privileged exploit demonstration, Windows/FreeBSD runtime validation, or a release supply-chain audit. Close the concrete findings, rerun the regressions, and obtain an independent review of the authentication and host-trust boundaries before treating the result as release assurance.
