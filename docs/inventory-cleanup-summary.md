# Inventory extraction cleanup summary

All seven remediation items from the API-boundary audit are complete. The final
change is Jujutsu `rozrwyol`; the earlier changes remain separate for review.

## Decisions made in the final pass

- **Denial reveals no reason.** Public HTTP 403 says only `access denied`.
  Rule labels, inventory membership, and other policy details stay in CA logs.
- **Pending is distinct from denial.** Policy HTTP 202 becomes public
  `authorization pending; try again later`. It produces no certificate and is
  represented by `caclient.PolicyPendingError`.
- **Retry is explicit.** Pending does not trigger token refresh, automatic
  polling, or CA failover. A later SSH attempt evaluates authorization again.
  No retry delay, approval URL, or upstream `Retry-After` header is exposed.
- **Only user authentication rejection triggers refresh.** Inventory lookup's
  401 becomes public 401. Policy's service-credential 401 and inventory's
  service-credential 403 become public 502. The broker still refreshes a rejected
  user token at most once per Match.
- **CA owns all public error messages and statuses.** Dependency failures,
  unexpected policy statuses, and invalid policy responses become generic 502.
  Internal CA failures become generic 500; malformed requests use fixed 400
  messages. Error responses use `Cache-Control: no-store`. Successful issuance
  still returns only the certificate.
- **Recovery respects the same outcome classes.** The circuit-breaker pool's
  recovery path now stops on pending, denial, or a user-authentication error,
  even when all CAs were previously marked unavailable. Previously it treated
  every error during recovery as an infrastructure failure.

The pending contract supports custom policies and library evaluators. The
built-in static CLI still registers no requirement plugins. This change adds no
approval store, background workflow engine, or automatic polling.

The complete status table and migration guidance are in [Public CA errors](ca-errors.md).

## Completed cleanup list

| YATL task | Result | Jujutsu change |
|---|---|---|
| `v0n79ah8` | Policy returns authorization limits; CA constructs identity and principal and enforces lifetime ceilings. | `vxmpympr` |
| `89sc9825` | Policy receives projected facts, independent of inventory transport metadata; revisions stay with CA audit. | `lloxrowl` |
| `hmh7yb8s` | User facts use plain fields and string groups; SCIM wrappers removed. | `rovooulx` |
| `20c03jnp` | POST lookup and GET discovery use the exact configured inventory endpoint. | `tnsxqzkn` |
| `ms54kqbp` | Fixed public error messages; private diagnostics remain in logs. | `rozrwyol` |
| `kkr7vee5` | Service-credential failures and user-authentication failures have distinct client behavior. | `rozrwyol` |
| `twperd14` | Generic pending response with explicit later retry. | `rozrwyol` |

Two additional agreed refinements remain separate: `qmsnlkyz` expresses policy
TTL as integer `ttlSeconds`; `knorwsqr` renames the inventory destination to
`target` and flattens `inventory.host`. `accounts: null` retains the agreed
meaning of no inventory account restriction; `[]` permits no accounts.

## Validation and rollout

- `make build` completed; because its binary target was already present, an
  explicit `go build ./cmd/epithet` also verified the current sources.
- `make test` passed, including policy, security, combined-server, and SSH tests.
- A fresh `go test -count=1 ./test/server` also passed, exercising subprocess
  deployment without relying on the Go test cache.
- `go test -race ./pkg/broker ./pkg/breakerpool` passed.
- Regression tests cover private error bodies and headers, discovery failures,
  malformed requests, certificate-only success, pending responses, token refresh,
  failover, and recovery after every CA has been marked unavailable.
- API schema checks passed for the revised inventory routes, matching user
  shapes, and the policy pending response.

Upgrade CA, inventory, and custom policies together for the changed contracts.
Upgrade clients for proper 202 handling; older clients classify it as a malformed
request. Proxy routes must preserve the configured inventory endpoint's signed
host and path. See [inventory migration](inventory.md#validation-and-migration)
and [custom policy migration](policy-server.md#custom-policy-migration-api-7).
