# Public CA errors

The CA returns fixed plain-text error messages with `Content-Type: text/plain`
and `Cache-Control: no-store`. HTTP status determines client behavior. Private
policy messages, rule labels, group membership, pending requirements, backend
URLs, filesystem paths, and audit revisions are never included in these bodies.
Diagnostics are recorded in CA server logs.

| Status | Public body | Client behavior |
|---|---|---|
| 202 | `authorization pending; try again later` | No certificate. Report pending; a later explicit request may succeed. |
| 400 | `invalid certificate request` | Correct the request; no automatic retry. |
| 401 | `invalid or expired authentication` | Broker forces one token refresh and retries once. |
| 403 | `access denied` | No certificate; no automatic retry. |
| 405 | `method not allowed` | Correct the request method. |
| 413 | `request too large` | Reduce the request size. |
| 500 | `internal CA error` | Infrastructure failure; eligible for CA failover. |
| 502 | `CA dependency unavailable` | Infrastructure failure; eligible for CA failover. |

Successful issuance remains HTTP 200 with only `{"certificate":"..."}`.
All other statuses, including 202, produce no certificate.

## Private service classification

CA interprets statuses in the context of the service and operation:

| Source | Private result | Public result |
|---|---|---|
| Inventory resolution | 401: user token rejected | 401 |
| Inventory resolution | Service authentication failure, unavailable service, or invalid response | 502 |
| Policy | 403: authorization denied | 403 with generic body |
| Policy | 202: authorization pending | 202 with generic body |
| Policy | 401: CA service credential rejected | 502 |
| Policy | Any other non-200 status, transport failure, or invalid authorization | 502 |
| Inventory discovery | Any upstream failure, including 401 | 502 |

Upstream statuses and response headers are not forwarded blindly. In particular,
refreshing a user's credentials cannot fix a rejected CA service credential.
Private policy denial and pending reasons stay in logs. The public response does
not distinguish a missing user, inactive user, missing host, account restriction,
or matching deny rule.

## Pending authorization

Custom policies and library evaluators can return 202 when asynchronous work
must finish before authorization can be granted. The client reports
`caclient.PolicyPendingError`. The broker fails the current Match with the
generic pending message. It does not force authentication refresh, fail over to
another CA, or poll automatically. A later SSH attempt evaluates authorization
again. Pending is not cached as a grant or a permanent denial.

The response does not identify the work in progress, promise eventual approval,
provide a polling URL, or specify a retry delay. Upstream `Retry-After` and
`Location` headers are not exposed. Clients receive a fixed message rather than
a policy-supplied explanation.

This contract does not add approval storage, background job execution, or plugin
registration to the built-in CLI. Those workflows remain separate work; the
static CLI policy server currently registers no requirement plugins.

Upgrade CA and clients together for pending support: older clients interpret 202
as a malformed request. Existing clients already classify 401, 403, and 5xx;
they must not parse the human-readable body to determine the outcome.
