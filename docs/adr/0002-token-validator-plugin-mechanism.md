# 0002: Token validator plugin mechanism

**Status:** Draft

## Context

The policy server currently validates tokens using OIDC only. The `TokenValidator` interface exists and is already the correct abstraction — the evaluator receives an opaque identity string and never touches OIDC claims directly — but `evaluator.New()` and `evaluator.NewWithProvider()` hardwire OIDC validator creation internally rather than accepting a validator as a parameter.

Operators who use non-OIDC identity providers (custom JWT issuers, enterprise SSO systems, or bespoke auth mechanisms) cannot use the built-in policy server without forking epithet.

The broker already has a pluggable auth mechanism: operators configure an auth command that runs as a subprocess, receives state on stdin, and writes a token to stdout. This works well for the broker — it runs on user endpoints where operators write shell scripts or small programs — but has different tradeoffs on the server side.

Three approaches were considered for policy server token validator plugins:

1. **Go interface only (recompile to extend):** The `TokenValidator` interface already exists. Operators implement it and recompile. Simple, no IPC overhead, but requires forking and maintaining Go code.

2. **Subprocess command (stdin/stdout protocol, mirroring broker):** Same per-invocation model as the broker's auth command. Simple to implement in any language. But: the policy server is a trusted, controlled service; per-request subprocess forks add latency at exactly the wrong point; the protocol is stringly typed; structured errors are awkward.

3. **gRPC over Unix socket:** Plugin runs as a persistent subprocess. Policy server passes a socket path via environment variable; plugin starts a gRPC server on that path; policy server connects at startup and holds the connection. Typed API via protobuf schema. Language-agnostic (Go, Python, Rust, and others all support Unix socket gRPC natively).

## Decision

Token validator plugins use gRPC over a Unix socket, with the socket path communicated via environment variable.

**Plugin lifecycle:**
1. Policy server generates a temp Unix socket path and sets `EPITHET_PLUGIN_SOCKET=<path>` in the plugin's environment.
2. Policy server spawns the plugin subprocess.
3. Plugin starts a gRPC server bound to that path.
4. Policy server connects and holds the connection for its lifetime.
5. Plugin health is monitored; the policy server restarts a crashed plugin with backoff.

**Why gRPC over Unix socket (not stdio):**

"gRPC over stdio" — HTTP/2 framed directly over stdin/stdout pipes — is not portably supported. Python's `grpcio` has no stdio transport. Rust's `tonic` can do it via custom connectors but it is not standard. Go has workarounds but they are unsupported. Unix socket gRPC, by contrast, is first-class in every language with a gRPC implementation.

The socket path via environment variable (rather than the plugin printing its address to stdout, as in HashiCorp go-plugin) avoids the plugin needing to parse a handshake protocol and simplifies plugin implementations in all languages.

**Why not per-invocation subprocess (like the broker):**

The broker's auth command runs on user endpoints where a bash script is a realistic implementation. The policy server is a controlled service; plugin authors are expected to write a small program, not a script. The persistent gRPC connection avoids per-request process overhead and gives a proper typed error model.

**Proto interface:**

```protobuf
service TokenValidator {
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
}

message ValidateTokenRequest {
  string token = 1;
}

message ValidateTokenResponse {
  string identity = 1;
  map<string, string> claims = 2; // optional; available to the evaluator
}
```

Validation failure is returned as a gRPC error status (UNAUTHENTICATED for invalid tokens, INTERNAL for plugin errors).

**Required code changes:**
- New package `pkg/policyserver/plugin/` with proto definitions, generated code, `GRPCTokenValidator` struct, and plugin lifecycle management.
- Add `evaluator.NewWithValidator()` constructor that accepts an external `TokenValidator`; remove OIDC construction from `New()` and `NewWithProvider()`.
- Add `token_validator_plugin` config field to `ServerConfig` (`{command string, args []string}`); relax `Validate()` to require OIDC only when no plugin is configured.
- Wire plugin startup and validator construction through `cmd/epithet/policy.go`.

## Consequences

- Operators with non-OIDC identity providers can use the built-in policy server without forking.
- Plugin authors write a small gRPC server in any language; the contract is the protobuf schema.
- The OIDC validator path is unchanged for operators who use OIDC.
- The optional `claims` map in the response is available to the evaluator for future use (e.g., passing group membership or custom attributes into policy evaluation) without requiring a protocol change.

**What this does not address:**
- `PolicyEvaluator` plugins — flexible policy evaluation (on-call checks, deployment windows, approval workflows, per-VM principal assignment) is deferred. It requires first settling questions about policy evaluation in the broker, state management in the policy server, and the overall policy model. That is a larger change.
- Broker auth plugin protocol — the existing stdin/stdout/fd3 protocol is not changed. There are no external users of the broker auth plugin system currently, so changing it to use gRPC is possible in the future, but there is no immediate reason to do so.

## Open questions

- Should the plugin be restartable without restarting the policy server? Hot-reload of plugins would improve operator experience but adds complexity to lifecycle management.
- Should `claims` from the token validator be available to a future `PolicyEvaluator` plugin, and if so, how are they passed through?
- Does the broker's auth command protocol warrant updating to gRPC in the future, for consistency? Deferred until there are external users and a clear reason.
