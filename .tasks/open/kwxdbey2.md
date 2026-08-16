---
yatl_version: 1
title: 'Security hardening: signature replay window, --insecure scope, plain-HTTP policy fetch'
id: kwxdbey2
created: 2026-06-23T16:52:29.964019493Z
updated: 2026-08-16T08:18:27.755350Z
author: Brian McCallister
priority: low
tags:
- security
- hardening
---

Hardening: defense-in-depth items from the security review. Low severity, grouped.

1) Replayable HTTP signatures (pkg/httpsig/httpsig.go:22-29)
   - 30s expiry + 60s skew window, no nonce/jti. CA->policy requests are replayable for ~90s. Low risk over unix socket/TLS, but a nonce or tighter window would harden the only authenticated channel into the policy server.

2) --insecure is broad and propagated (pkg/tlsconfig/tlsconfig.go:39)
   - InsecureSkipVerify applies to CA, OIDC discovery/JWKS, AND policy fetch; cmd/epithet/server.go:134 forwards it to all subprocesses. One flag disables all cert verification, including OIDC signing-key retrieval. Consider scoping more narrowly and/or a louder runtime warning.

3) Dynamic policy fetched over plain HTTP (pkg/policyserver/loader.go:99)
   - loadFromHTTP accepts http:// for the security-critical policy document with no integrity check; tlsconfig.ValidateURL is NOT applied here. Operator-controlled URL, but an on-path attacker on that hop could rewrite authorization rules. Enforce https:// (or signature) for remote policy URLs.

4) Stale run-dir cleanup trusts PID liveness (cmd/epithet/agent.go cleanupStaleRunDirs)
   - A recycled PID can keep a dead broker run dir alive, or a same-named live process blocks cleanup. Reliability nit, not a direct vuln.

---
# Log: 2026-06-23T16:52:29Z Brian McCallister

Created task.

---
# Log: 2026-08-16T08:18:27Z Brian McCallister

Slimmed post-refactor: item 1 (signature replay window) is overtaken - RFC 9421 signing was replaced by 60s request-bound service JWTs (aud, exp, jti minted, body-hash, htm/htu method+target binding), leaving only jti-uniqueness tracking as a possible future hardening (needs CA<->policy MITM to exploit). Remaining live scope: --insecure is one global switch covering CA, JWKS, and policy fetch; plain-HTTP policy fetch guard.
