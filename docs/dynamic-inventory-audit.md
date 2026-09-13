# Dynamic inventory follow-up audit

This audit traces the implementation and review corrections against the workflow
agreed in this conversation. It does not treat every choice in the original
implementation summary as an approved requirement.

## Corrected in this pass

| Finding | Correction |
| --- | --- |
| Token creation still returned both an ID and a separate secret after adopting token = filename = host ID. | Removed the redundant return value and API field; the CLI and broker use the token ID. |
| YAML serialization changed unrestricted accounts from null to an empty list. Saving through the editor or restarting inventory could therefore deny previously permitted accounts. | Preserve null, empty lists, and populated lists through YAML serialization, persistence, restart, and editing. |
| Pending enrollment still rejected overlaps with approved or exact static hosts before admin review. | Accept the pending record; check conflicts at approval. Token enrollment still checks conflicts before consuming the token because it approves immediately. |
| The editor required an additional submit/save confirmation even after a valid exit. | A valid editor exit proceeds. An empty file cancels; invalid YAML offers re-edit/cancel. The separate admin approve/edit/deny/exit review remains. |
| Static exact lookups still succeeded after a managed write failure, silently serving a partial static-only inventory. | The failed-store check applies to every managed lookup, including static exact records. Configured storage must load at startup, and write failures stop further operations through that store. |
| The existing inventory check command validated only static files. | Check the configured managed files using the same loader and exclusive lock as startup; the writer must be stopped, and no OIDC connection is needed for the check. |
| Moving the inventory URL into its client introduced a second independent CA bootstrap request during agent startup. | Return auth configuration, public CA URL, and inventory URL from one discovery operation and the same CA root response. Remove the extra discovery method. |
| The public CA URL was named as though it were a separate enrollment endpoint. | Rename it to publicCAURL. Its only inventory use is the CA address in the printed token enrollment command. |
| CLI YAML presentation still claimed to hide removed credential hashes and converted integer revisions through float64. | Keep API field names/source metadata and preserve integer revisions when presenting YAML. |
| CLI handling interpreted a generic broker error as evidence of an old unsupported agent. | Report the actual broker error, without an invented upgrade diagnosis. |
| Even a full record ID caused the CLI to download the entire inventory. | Use the existing indexed get operation for full IDs. Name and prefix convenience lookup still uses listing. |

Also removed redundant proposal validation and updated the affected tests,
protocol descriptions, and workflow documentation.

## Implementation assumptions still present, not approved requirements

These are findings for discussion. This pass does not choose replacement behavior.

| Area | Current behavior and consequence |
| --- | --- |
| Wildcard admission and tombstones | Pending, denied, removed, and retired names block static wildcard matches. An anonymous pending submission can therefore prevent access to a host that previously resolved through a wildcard. Removing a record retains its tombstone; editing away a pending name does too. This is a substantive admission policy, not merely storage bookkeeping. |
| Fixed operational limits | Enrollment shares a global burst of 20 and sustained rate of one request/second, including token enrollment. The pending queue is capped at 1,000, proposals at 64 names, and token lifetime at 24 hours. Only the one-hour default was agreed; these other numbers were implementation choices. |
| Additional commands and retained history | Token listing/revocation and an audit command were added beyond token creation. Every item retains audit history, and a redeemed host retains token metadata. There is no history compaction or expiry-based file cleanup. The need and shape of these features were not settled. |
| Principal-domain restrictions | Managed proposals permit generated per-host domains only, and approved records cannot share a generated domain. Existing static inventory has named/shared-domain semantics. The managed restriction needs an explicit scope decision. |
| Runtime storage failure | A failed write marks the store unavailable until restart, even if the write failed before publication. The process stays running and returns errors. Static-only fallback is removed, but whether a runtime storage error should terminate the process or be handled otherwise remains an operational decision. |

## Existing limitations to keep explicit

- Static configuration accepts files/globs, not a managed snapshot directory.
  Snapshot-as-static and object-store support were discussed as possibilities;
  neither is implemented.
- Users and admin grants remain static. There is no dynamic user provisioning or SCIM.
- Admin names/prefixes still use a full listing. Lists and audit responses have no
  pagination and are bounded by the client's response-size limit. Full IDs now
  avoid that dependency.
- Direct file edits require stopping and restarting inventory. There is no watcher.
- The current item format still has a version/kind wrapper and nested host data.
  It supports one format only, with no migration or compatibility reader.

## Confirmed boundaries

No enrollment credential file, credential hash/index, retry-identity mechanism,
proposal-file/yes flags, DNS lookup, legacy-record migration, or degraded startup
path remains. Ordinary local CA trust and SSH principal-domain files predate
managed inventory and are still needed by host enrollment.

Inventory management HTTP operations live in inventoryclient. The CA only
advertises the management link. The router proxies CA and inventory management;
policy and inventory resolution stay private. Exact static hosts override
dynamic records after the configured store loads successfully.

## Validation

Regression tests cover null/list account persistence and editor behavior, pending
conflict resolution by editing either record, checking corrupt managed files,
single-bootstrap discovery, precise displayed revisions, and failed-store
behavior. The full repository suite and race checks cover the affected broker,
inventory, client, and server packages.
