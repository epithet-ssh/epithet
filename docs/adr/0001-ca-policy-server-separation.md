# 0001: CA and policy server separation

**Status:** Draft

## Context

Epithet has two server-side components: the CA server, which signs SSH certificates, and the policy server, which validates tokens and evaluates access policy. Both are in the same repository and compiled from the same binary. A `server` subcommand runs them together for simple deployments.

The question of whether to merge them into a single process recurs. The arguments for merging are:

- Simpler deployment (one process to run and monitor).
- Eliminates the HTTP round-trip from CA to policy server on every certificate request.
- Eliminates need to authenticate requests between CA and policy server
- The combined server already runs them as subprocesses of the same binary, making the "separation" partially fictional.

## Decision

Keep the CA and policy server as separate components.

**Rationale:**

The separation is load-bearing for high-availability deployments. Running multiple stateless policy server instances behind a load balancer — the documented production deployment model — requires a real network boundary between CA and policy server. Merging them would make horizontal scaling of the policy server impossible without also scaling the CA and its signing key.

The CA holds the SSH signing private key. The policy server handles raw identity tokens from brokers. These have genuinely different security postures: the CA should be minimally exposed and tightly controlled, while the policy server can be a horizontally scalable, read-heavy service. Keeping them separate preserves the option to operate them under different security controls.

**Authentication between CA and policy server:**

The Sigstore signature verification (CA signs the request body; policy server verifies it) adds cryptographic overhead on every certificate request. The argument was made that this overhead is only necessary when an external, untrusted policy server is in use — that in same-machine deployments it is theater.

This argument is rejected. Consistent behavior across deployment modes is more valuable than the savings from skipping crypto in the embedded case. Allowing different code paths creates drift: bugs that only manifest in one mode, behavior that operators cannot rely on being consistent. The Sigstore verification stays in all modes. If it becomes a measured production bottleneck, we will optimize then, with data.

**On the current policy server:**

The current policy server is a reference implementation suitable for simple deployments and development. It is intentionally stateless, file-based, and OIDC-only. Production deployments with dynamic infrastructure — VM fleets, on-call-gated access, approval workflows — are expected to implement more sophisticated policy servers. The `--policy <url>` configuration option supports this. The reference implementation is not designed to be replaced by external contributors; it is designed to be evolved by the project.

## Consequences

- The `server` subcommand combined deployment remains as-is (subprocess-based). The subprocess approach produces consistent behavior with separate deployments, which is the point.
- The Sigstore verification remains in all deployment modes.
- `--policy <url>` stays as an escape hatch for operators with unusual requirements, but it is not a primary extensibility story.
- The policy server will need to become stateful as epithet matures — to support dynamic `(host, user) → principal` mappings for cloud environments with ephemeral VMs, approval workflows, and richer authorization signals. That evolution will happen within the existing policy server, not by plugging in replacement implementations.

## Open questions

- What does flexible policy evaluation look like? Current evaluation is tag-based and stateless. Supporting on-call checks, deployment windows, and per-VM principal assignment requires either external signal integration (reads against PagerDuty, CI/CD systems) or local state (principal mapping database). The right model for this is not yet settled and has implications for broker-side matching as well.
- How should `(host, user) → principal` mappings be managed in dynamic environments? An `epithet host` management command has been discussed but not designed.
- The `server.go` combined server runs both components as child subprocesses via `exec.CommandContext`. This is operationally fragile but produces consistent behavior. Whether to refactor it (to in-process goroutines or otherwise) remains open.
