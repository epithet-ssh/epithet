# CLI flag audit

Snapshot: 2026-09-28, current working copy after the naming cleanup and flat TOML config lookup implementation.

**71 distinct long flags; 29 runnable command paths.** Extracted from the actual Kong model without loading user configuration or starting services. Meanings and runtime notes were checked against the command implementations.

This describes implemented behavior. Proposed shared `--key-file`, `--source`, and `--static-file` names are **not implemented**. Neither `--directory-public-url` nor the proposed `--directory-lookup-url` / `--directory-admin-url` exists. The public management advertisement is `--control-public`.

## How to read this audit

- Commands omit the leading `epithet`. `agent *`, `directory *`, and `inventory *` mean the named parent and all of its subcommands; the command inventory below enumerates them.
- **Accepted** means the parser accepts the option on that command path. It does not imply the handler uses the option. Inherited-but-unused cases are called out explicitly.
- **CLI-only for `match`:** `--host`, `--port`, `--user`, `--hash`, `--jump`, and `--broker-socket` receive values only from command-line arguments. Config values for these flags are ignored, and they have no environment bindings. Required flags must appear on the command line; omitted `--jump` stays empty. Global logging settings remain configurable. Other commands' `--broker-socket` flags remain configurable.
- Endpoint flags omit the `-url` suffix and show `URL` as their value placeholder in help (for example, `--ca=URL`). The existing `--oidc-issuer` name also uses this placeholder.
- The metadata tables show parser defaults, required markers, short aliases, and explicit flag-bound environment variables. Runtime defaults and runtime-required values are described in the notes.
- `—` under Environment means no environment binding is declared for that flag. The application can still consult environment variables for platform paths or login detection; those are not alternate names for the flag.
- All command paths inherit the seven global flags. Parent options are accepted by descendants. Long flag aliases are not declared; command aliases are listed below.
- **Internal to `server`:** `router` and its local `--listen`, `--ca-backend`, and `--control-backend` flags are hidden from help. They remain accepted for subprocess invocation and are included here for auditing. Other commands' `--listen` flags remain public.

## Runtime caveats worth auditing

1. Directory and inventory administrative commands inherit listener, mode, file, trust-key, state, and check flags from their server-oriented parent. Their handlers use agent transport, not those local service settings.
2. Agent identity/login/logout/inspect/kill inherit CA connection and login-method settings, but use the running broker; these flags do not reconfigure it.
3. Control accepts `--oidc-client-secret` through its shared OIDC struct, but does not consume that field.
4. `policy --check` is redundant: the policy command always validates and exits.
5. `--listen` defaults differ: CA and the combined launcher default to all interfaces; the other standalone listeners default to loopback. Only CA has the `PORT` environment binding.
6. Verbosity help says debug/trace, but the logger implements info/debug for `-v`/`-vv`.
7. The combined launcher exposes only a subset of child flags. It passes explicit listener, endpoint, trust-key, and identity settings to children; those override child config values. There is no general per-child config-file selection option.
8. Main parsing and child reparsing layer explicit `--config` over default-file resolvers. See the `--config` entry.

## Flag catalog

### --after

Return events after this audit sequence.

**Accepted by:** `directory groups audit`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `directory groups audit` | uint64 | `0` | no | — | — |

**Runtime / audit note:** Directory audit sequence cursor: returns events after this sequence, not a timestamp.

### --agent-name

Declared meanings:

- `agent *`: Profile name; names the rundir and the ssh Tag (epithet-<name>, or just epithet for the default profile).
- `inventory *`: Agent profile for administrative commands.
- `directory *`: Agent profile for administrative commands.

**Accepted by:** `agent *`, `inventory *`, `directory *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent *` | string | `default` | no | — | — |
| `inventory *` | string | `default` | no | — | — |
| `directory *` | string | `default` | no | — | — |

**Runtime / audit note:** On `agent start`, names the running profile, runtime directory, and SSH tag. Other agent commands use it to locate that profile. Directory/inventory administration defaults to the configured `agent-name`, then `default`. Serving directory/inventory does not use it.

### --authorized-principals-command-user

Unprivileged account used for AuthorizedPrincipalsCommand.

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | `nobody` | no | — | — |

**Runtime / audit note:** Local unprivileged account under which sshd invokes the generated AuthorizedPrincipalsCommand. Not the account being authorized and not the Epithet daemon user.

### --broker-socket

Declared meanings:

- `agent login`: Broker socket path (overrides profile discovery).
- `agent logout`: Broker socket path (overrides profile discovery).
- `agent identity`: Broker socket path (overrides profile discovery).
- `agent inspect`: Broker socket path (overrides config-based discovery).
- `agent kill`: Broker socket path (overrides config-based discovery).
- `match`: Broker socket path.
- `inventory *`: Agent broker socket override for administrative commands.
- `directory *`: Agent broker socket override for administrative commands.

**Accepted by:** `agent login`, `agent logout`, `agent identity`, `agent inspect`, `agent kill`, `match`, `inventory *`, `directory *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent login` | string | unset | no | `-b` | — |
| `agent logout` | string | unset | no | `-b` | — |
| `agent identity` | string | unset | no | `-b` | — |
| `agent inspect` | string | unset | no | `-b` | — |
| `agent kill` | string | unset | no | `-b` | — |
| `match` | string | unset | yes | `-b` | — |
| `inventory *` | string | unset | no | — | — |
| `directory *` | string | unset | no | — | — |

**Runtime / audit note:** Required for `match`. On agent subcommands and directory/inventory administration, overrides profile-based socket discovery. Directory/inventory serving does not use it.

### --ca

Declared meanings:

- `agent *`: CA URL (repeatable, format: priority=N:https://url or https://url).
- `host enroll`: CA bootstrap URL.

**Accepted by:** `agent *`, `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent *` | string (repeatable) | empty collection | no | `-c` | — |
| `host enroll` | string | unset | yes | — | — |

**Runtime / audit note:** Agent startup accepts multiple endpoints and optional `priority=N:` prefixes for failover. Host enrollment accepts one endpoint (the same URL parser accepts a priority prefix, but enrollment does not use its priority). Both use CA bootstrap discovery. Agent session/inspection subcommands inherit this option but use the running broker instead.

### --ca-backend

Private CA Unix socket URL. **Internal to `server`; hidden from help.**

**Accepted by:** `router`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `router` | string | unset | yes | — | — |

**Runtime / audit note:** Private router upstream, currently restricted to an absolute `unix:///...` socket URL. The router forwards CA routes here. Unlike the agent’s `--ca`, it is a single private proxy destination, not a failover list.

### --ca-cooldown

Circuit breaker cooldown for failed CAs.

**Accepted by:** `agent *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent *` | duration | `10m` | no | — | — |

**Runtime / audit note:** Used when starting the agent’s CA client. Other agent subcommands inherit it but do not reconfigure the running agent.

### --ca-key-file

Declared meanings:

- `ca`: Path to ca private key.
- `server`: Path to CA private key.

**Accepted by:** `ca`, `server`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `ca` | string | `/etc/epithet/ca.key` | no | `-k` | — |
| `server` | string | `/etc/epithet/ca.key` | no | — | — |

**Runtime / audit note:** The CA private signing key. The combined launcher reads it, derives the trusted CA public key for the fact services, and passes the private-key path to its CA child. Distinct from the control key.

### --ca-public-key

Declared meanings:

- `inventory *`: CA public key (URL, file path, or literal SSH key).
- `directory *`: CA public key for fact reads.

**Accepted by:** `inventory *`, `directory *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory *` | string | unset | no | — | — |
| `directory *` | string | unset | no | — | — |

**Runtime / audit note:** A trust input: accepts an SSH public-key literal, file path, or HTTP(S) URL. Used by directory/inventory serving to authenticate CA requests. Required at serving startup, except when running `--check`; not parser-required. Administration subcommands inherit it but do not use it.

### --ca-public-key-file

CA public-key file (default: epithet-ca.pub beside the domain file).

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |

**Runtime / audit note:** An output/local-state path for host enrollment, not the flexible public-key trust input used by services. Defaults to `epithet-ca.pub` beside the principal-domain file; existing managed enrollment can supply the previous path.

### --ca-timeout

Per-request timeout for CA requests.

**Accepted by:** `agent *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent *` | duration | `15s` | no | — | — |

**Runtime / audit note:** Used when starting the agent’s CA client. Other agent subcommands inherit it but do not reconfigure the running agent.

### --certificate-default-ttl

Default certificate expiration when no rule sets a ttl (e.g., 5m).

**Accepted by:** `ca`, `policy`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `ca` | string | unset | no | — | — |
| `policy` | string | unset | no | — | — |

**Runtime / audit note:** A Go duration string, such as `5m`. Runtime default is five minutes when no Writ rule supplies a TTL; certificate lifetime is also bounded by authentication expiry. `server` does not expose this flag directly; its CA child can read it from the CA config section.

### --certificate-extension

Declared meanings:

- `ca`: Certificate extension for issued certs (name=value, repeatable; default permit-pty, permit-agent-forwarding, permit-user-rc).
- `policy`: Certificate extension for issued certs (name=value, repeatable; default permit-pty, permit-agent-forwarding, permit-user-rc).
- `server`: Certificate extension for issued certs (name=value, repeatable).

**Accepted by:** `ca`, `policy`, `server`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `ca` | name=value (repeatable) | empty collection | no | — | — |
| `policy` | name=value (repeatable) | empty collection | no | — | — |
| `server` | name=value (repeatable) | empty collection | no | — | — |

**Runtime / audit note:** Repeatable `name=value` map entries. Runtime defaults are `permit-pty`, `permit-agent-forwarding`, and `permit-user-rc`, with empty values. A nonempty configured map replaces those defaults. The launcher forwards configured entries to its CA child.

### --check

Declared meanings:

- `inventory *`: Validate inventory files, then exit.
- `directory *`: Validate directory configuration and storage.
- `policy`: Validate the policy, then exit.

**Accepted by:** `inventory *`, `directory *`, `policy`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory *` | bool | `false` | no | — | — |
| `directory *` | bool | `false` | no | — | — |
| `policy` | bool | `false` | no | — | — |

**Runtime / audit note:** Directory/inventory serving loads and validates data/storage and returns before listening or requiring the CA public key. Managed storage may be initialized; this is not guaranteed to be read-only. Administration subcommands inherit it but ignore it. `policy` always validates and exits, whether or not this flag is supplied.

### --compact

Show one line per agent (default without an ID).

**Accepted by:** `agent inspect`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent inspect` | bool | `false` | no | — | — |

**Runtime / audit note:** Mutually exclusive with `--expanded` and `--json`. This is the default display when no agent ID is supplied.

### --config

Path to config file.

**Accepted by:** All commands.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| All commands | file path | unset | no | — | — |

**Runtime / audit note:** Flat TOML; top-level keys are exact long flag names with no command namespace. Kong looks up only the selected command's flags, so unrelated keys are ignored. Arrays supply complete list values; duplicate keys within one file are errors. Precedence is CLI, config, declared environment binding, then built-in default. Default discovery scans `/etc/epithet/*.toml` and `~/.epithet/*.toml` in that order, sorted by filename within each directory. Later files replace earlier values; explicit `--config` adds the last resolver, with omitted keys still falling back to default files. The supervisor forwards `--config` to children and uses the same default files for its CA-identity reparse. YAML/JSON service configs are no longer supported; static data remains YAML.

### --control-backend

Private control Unix socket URL (enables /inventory and SCIM). **Internal to `server`; hidden from help.**

**Accepted by:** `router`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `router` | string | unset | no | — | — |

**Runtime / audit note:** Private router upstream, currently restricted to an absolute `unix:///...` socket URL. Enables routing `/inventory` to control’s `/manage` and forwarding `/scim/v2/...`. Empty disables those routes.

### --control-key-file

Declared meanings:

- `control`: Configured control signing key.
- `server`: Path to configured control signing key.

**Accepted by:** `control`, `server`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | `/etc/epithet/control.key` | no | — | — |
| `server` | string | `/etc/epithet/control.key` | no | — | — |

**Runtime / audit note:** The control private signing key for authenticated calls to fact services. The combined launcher derives its public key and supplies it to the fact services. The launcher requires this key to differ from the CA key.

### --control-public

Client-accessible control URL advertised at bootstrap.

**Accepted by:** `ca`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `ca` | string | unset | no | — | — |

**Runtime / audit note:** Client-accessible management endpoint advertised by CA through its control Link relation. Accepts an HTTP(S) URL or relative URL; it does not set a listener. In combined mode the launcher supplies `inventory`, which the router maps to control’s `/manage` endpoint.

### --control-public-key

Declared meanings:

- `inventory *`: Control service public key for administration.
- `directory *`: Control public key for administration.

**Accepted by:** `inventory *`, `directory *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory *` | string | unset | no | — | — |
| `directory *` | string | unset | no | — | — |

**Runtime / audit note:** A trust input: accepts an SSH public-key literal, file path, or HTTP(S) URL. Used by directory/inventory serving for control-signed calls and private administration. Omitting it leaves those management endpoints unregistered. Administration subcommands inherit it but do not use it.

### --directory

Declared meanings:

- `control`: Directory fact service URL.
- `ca`: Directory service URL.

**Accepted by:** `control`, `ca`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | yes | — | — |
| `ca` | string | unset | yes | — | — |

**Runtime / audit note:** Private directory fact-provider root used by CA and control; the client appends `/lookup`. It is not advertised to end users. Can point to a custom lookup-only provider.

### --directory-admin-group

Directory administrator groups.

**Accepted by:** `control`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string (repeatable) | empty collection | no | — | — |

**Runtime / audit note:** Repeatable policy group names granting the corresponding administrator role. Membership comes from directory facts, and the actor must be active. Directory and inventory grants are independent.

### --directory-admin-user

Directory administrator user IDs.

**Accepted by:** `control`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string (repeatable) | empty collection | no | — | — |

**Runtime / audit note:** Repeatable directory user IDs granted the corresponding administrator role. The authenticated actor must exist and be active. These are identity IDs, not usernames or SCIM resource IDs.

### --directory-backend

Built-in directory administration service URL.

**Accepted by:** `control`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | — |

**Runtime / audit note:** Optional private administration backend root used by control for directory management, actor checks, and SCIM. Usually the same directory service as `--directory`, but the two are configured independently. Omit when the directory provider implements facts only.

### --directory-mode

Directory mode: static files or SCIM provisioning.

**Accepted by:** `directory *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `directory *` | string; `static`, `scim` | `static` | no | — | — |

**Runtime / audit note:** Used only for directory serving: `static` loads user/group facts from files; `scim` opens managed SQLite storage. Directory administration subcommands inherit this flag but operate through the running agent.

### --directory-static-file

Declared meanings:

- `directory *`: Static directory files or globs.
- `server`: Static directory file path or glob (repeatable).

**Accepted by:** `directory *`, `server`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `directory *` | string (repeatable) | empty collection | no | — | — |
| `server` | string (repeatable) | empty collection | no | — | — |

**Runtime / audit note:** Repeatable paths/globs for static directory data. Directory serving uses these only in static mode. `server` forwards its entries only to directory. Administration subcommands inherit the option but do not use it.

### --epithet-binary

Epithet executable written into AuthorizedPrincipalsCommand.

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |

**Runtime / audit note:** Path written into the generated AuthorizedPrincipalsCommand. Runtime default is the current executable.

### --expanded

Show full details (default with an ID).

**Accepted by:** `agent inspect`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent inspect` | bool | `false` | no | — | — |

**Runtime / audit note:** Mutually exclusive with `--compact` and `--json`. This is the default display when an agent ID is supplied.

### --expires-in

Lifetime (maximum 24h).

**Accepted by:** `inventory token create`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory token create` | duration | `1h` | no | — | — |

**Runtime / audit note:** Lifetime of a new enrollment token: default one hour; runtime validation allows one second through 24 hours. Not certificate TTL.

### --hash

Connection hash (%C).

**Accepted by:** `match`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `match` | string | unset | yes | `-C` | — |

**Runtime / audit note:** OpenSSH connection hash `%C`, identifying the connection-specific agent.

### --help

Show context-sensitive help.

**Accepted by:** All commands.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| All commands | switch | off | no | `-h` | — |

**Runtime / audit note:** Shows help without running the requested command.

### --host

Remote host (%h).

**Accepted by:** `match`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `match` | string | unset | yes | `-H` | — |

**Runtime / audit note:** SSH destination hostname, normally OpenSSH `%h`; used for matching and certificate requests. Not an enrollment name or a profile selector.

### --host-name

Proposed DNS name (repeatable; overrides detection).

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string (repeatable) | empty collection | no | — | — |

**Runtime / audit note:** Repeatable proposed DNS names for enrollment; overrides local detection. This is separate from the agent profile name and the SSH destination `--host`.

### --insecure

Disable TLS certificate verification (NOT RECOMMENDED).

**Accepted by:** All commands.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| All commands | bool | `false` | no | — | `EPITHET_INSECURE` |

**Runtime / audit note:** Disables outbound TLS certificate verification and permits HTTP URLs in clients using the TLS configuration. It does not enable an HTTPS listener. Accepted globally even by offline/local-socket commands that do not use outbound TLS.

### --inventory

URL for inventory service.

**Accepted by:** `ca`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `ca` | string | unset | yes | — | — |

**Runtime / audit note:** Private inventory fact-provider root used by CA; the client appends `/lookup`. It is not the client-facing management address.

### --inventory-admin-group

Inventory administrator groups.

**Accepted by:** `control`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string (repeatable) | empty collection | no | — | — |

**Runtime / audit note:** Repeatable policy group names granting the corresponding administrator role. Membership comes from directory facts, and the actor must be active. Directory and inventory grants are independent.

### --inventory-admin-user

Inventory administrator user IDs.

**Accepted by:** `control`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string (repeatable) | empty collection | no | — | — |

**Runtime / audit note:** Repeatable directory user IDs granted the corresponding administrator role. The authenticated actor must exist and be active. These are identity IDs, not usernames or SCIM resource IDs.

### --inventory-backend

Built-in inventory administration service URL.

**Accepted by:** `control`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | — |

**Runtime / audit note:** Optional private host administration backend root used by control. The management endpoint is `/manage`. This is distinct from CA’s inventory fact lookup destination.

### --inventory-mode

Host inventory mode: static files only, or enrollment with optional static files.

**Accepted by:** `inventory *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory *` | string; `static`, `enrollment` | `enrollment` | no | — | — |

**Runtime / audit note:** Used only for inventory serving: `static` loads host files; `enrollment` adds enrolled hosts and permits optional static files. Inventory administration subcommands inherit this flag but operate through the running agent.

### --inventory-static-file

Declared meanings:

- `inventory *`: Static inventory file path or glob (repeatable; optional in enrollment mode).
- `server`: Static inventory file path or glob (repeatable).

**Accepted by:** `inventory *`, `server`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory *` | string (repeatable) | empty collection | no | — | — |
| `server` | string (repeatable) | empty collection | no | — | — |

**Runtime / audit note:** Repeatable paths/globs for static host data. Static mode requires matching files; enrollment mode permits omission. `server` forwards its entries only to inventory. Administration subcommands inherit the option but do not use it.

### --json

Declared meanings:

- `agent identity`: Output in JSON format instead of tab-delimited fields.
- `agent inspect`: Output in JSON format.
- `directory users list`: Print the complete user snapshot as JSON.
- `directory groups list`: Print the complete binding snapshot as JSON.

**Accepted by:** `agent identity`, `agent inspect`, `directory users list`, `directory groups list`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent identity` | bool | `false` | no | `-j` | — |
| `agent inspect` | bool | `false` | no | `-j` | — |
| `directory users list` | bool | `false` | no | — | — |
| `directory groups list` | bool | `false` | no | — | — |

**Runtime / audit note:** On `agent inspect`, mutually exclusive with `--compact` and `--expanded`. JSON output shape depends on the command.

### --jump

ProxyJump configuration (%j).

**Accepted by:** `match`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `match` | string | unset | no | `-j` | — |

**Runtime / audit note:** OpenSSH ProxyJump configuration `%j`; optional connection context.

### --limit

Maximum events to return (1-1000; default 100).

**Accepted by:** `directory groups audit`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `directory groups audit` | int | `0` | no | — | — |

**Runtime / audit note:** Requested directory audit page size. Runtime default is 100 when omitted; maximum is 1000. Kong itself supplies zero when omitted.

### --listen

Declared meanings:

- `control`: Control listener.
- `ca`: Address to listen on.
- `inventory *`: Address to listen on.
- `directory *`: Private directory listener.
- `router`: HTTP address to listen on.
- `server`: Public address to listen on.

**Accepted by:** `control`, `ca`, `inventory *`, `directory *`, `router`, `server`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | `127.0.0.1:9996` | no | — | — |
| `ca` | string | `0.0.0.0:8080` | no | `-l` | `PORT` |
| `inventory *` | string | `127.0.0.1:9998` | no | `-l` | — |
| `directory *` | string | `127.0.0.1:9997` | no | — | — |
| `router` | string | `127.0.0.1:8080` | no | `-l` | — |
| `server` | string | `:8080` | no | `-l` | — |

**Runtime / audit note:** The listener of the invoked service: TCP address or `unix:///...` Unix socket URL. For `server`, selects the public router listener; the launcher passes explicit private socket listeners to its children. Directory/inventory administration subcommands inherit it but never start a listener. Defaults vary by command; only CA binds the environment variable `PORT`.

### --log-file

Path to log file (supports ~ expansion).

**Accepted by:** All commands.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| All commands | string | unset | no | — | `EPITHET_LOG_FILE` |

**Runtime / audit note:** Optional log destination; `~` is expanded. Without a path, logging uses stderr. Logger setup is global, including local/offline commands.

### --login-method

Interactive login method.

**Accepted by:** `agent *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `agent *` | string; `auto`, `browser`, `device` | `auto` | no | — | — |

**Runtime / audit note:** `auto` selects device authorization under SSH and browser login otherwise. Used at agent startup; session commands use the running broker’s login configuration.

### --oidc-client-id

OIDC client ID.

**Accepted by:** `control`, `ca`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | — |
| `ca` | string | unset | no | — | — |

**Runtime / audit note:** OIDC client ID / expected audience. In combined mode the launcher copies CA’s resolved client ID to control.

### --oidc-client-secret

OIDC client secret (for confidential clients).

**Accepted by:** `control`, `ca`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | — |
| `ca` | string | unset | no | — | — |

**Runtime / audit note:** CA includes this value in its discovered authentication configuration for clients. Control accepts the flag through the shared OIDC struct, but its startup code does not consume it. The combined launcher does not forward the CA client secret to control.

### --oidc-identity-mode

Identity mode: stable-id (default) or verified-email.

**Accepted by:** `control`, `ca`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | `EPITHET_OIDC_IDENTITY_MODE` |
| `ca` | string | unset | no | — | `EPITHET_OIDC_IDENTITY_MODE` |

**Runtime / audit note:** Runtime values are `stable-id` (default) and `verified-email`. This enum is validated by the OIDC implementation rather than a Kong enum tag. Combined mode copies CA’s resolved identity mode to control.

### --oidc-issuer

OIDC issuer URL.

**Accepted by:** `control`, `ca`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | — |
| `ca` | string | unset | no | — | — |

**Runtime / audit note:** OIDC identity-provider issuer URL for CA authentication or control administration authentication. In combined mode the launcher copies CA’s resolved issuer to control.

### --oidc-user-id-claim

JWT claim mapped to inventory id in stable-id mode, including email without verification checks (default: oid for Microsoft Entra, sub otherwise).

**Accepted by:** `control`, `ca`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | `EPITHET_OIDC_USER_ID_CLAIM` |
| `ca` | string | unset | no | — | `EPITHET_OIDC_USER_ID_CLAIM` |

**Runtime / audit note:** Claim selecting the stable user ID in stable-id mode; setting an override in verified-email mode is rejected. Runtime default is `oid` for Microsoft Entra and `sub` otherwise. Combined mode copies CA’s resolved claim setting to control.

### --pending

Show only pending requests.

**Accepted by:** `inventory list`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory list` | bool | `false` | no | — | — |

### --policy-file

Path to the writ policy file.

**Accepted by:** `ca`, `policy`, `server`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `ca` | string | unset | no | — | — |
| `policy` | string | unset | no | — | — |
| `server` | string | unset | no | — | — |

**Runtime / audit note:** Writ policy file. Runtime-required for CA issuance and offline policy validation, though not marked required in Kong. The launcher forwards it when supplied; otherwise the child reads its CA configuration.

### --port

Remote port (%p).

**Accepted by:** `match`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `match` | uint | `0` | yes | `-p` | — |

**Runtime / audit note:** SSH destination port, normally OpenSSH `%p`; not a service listener.

### --principal-domain

Proposed principal domain (default: reuse the local domain file's value or generate one).

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |

**Runtime / audit note:** Host enrollment reuses an existing local domain or generates one if this value is omitted. The domain is issuance metadata, not a DNS suffix.

### --principal-domain-file

Declared meanings:

- `host enroll`: Principal-domain file (default: native system state directory).
- `host authorized-principals`: Principal-domain file.

**Accepted by:** `host enroll`, `host authorized-principals`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |
| `host authorized-principals` | string | unset | yes | — | — |

**Runtime / audit note:** Host enrollment defaults to a `domain` file under native system state storage and can recover an existing enrollment’s path. `host authorized-principals` requires the path explicitly. Used to derive account-specific principals offline.

### --principal-mode

Declared meanings:

- `host enroll`: Principal mode to accept: account-name or epithet-principal-v1 (default: epithet-principal-v1; account-name on Windows).
- `inventory *`: Default host principal mode.
- `server`: Override inventory principal mode: account-name or epithet-principal-v1 (default: inherit inventory configuration).

**Accepted by:** `host enroll`, `inventory *`, `server`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |
| `inventory *` | string; `account-name`, `epithet-principal-v1` | `epithet-principal-v1` | no | — | — |
| `server` | string | unset | no | — | — |

**Runtime / audit note:** Inventory serving sets the default host principal scheme; host enrollment selects the scheme to accept locally. Values are `account-name` or `epithet-principal-v1`. Inventory defaults to `epithet-principal-v1`; fresh enrollment defaults to that except on Windows (`account-name`) and can recover an existing enrollment’s choice. An unset server override inherits inventory configuration. Inventory administration subcommands inherit this flag but do not use it.

### --quiet

Print only the token value.

**Accepted by:** `inventory token create`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory token create` | bool | `false` | no | — | — |

**Runtime / audit note:** On token creation, prints only the token value instead of the explanatory text and enrollment command.

### --revision

Directory revision shown by groups list.

**Accepted by:** `directory groups bind`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `directory groups bind` | uint64 | `0` | yes | — | — |

**Runtime / audit note:** Expected directory revision for binding a policy alias to a SCIM group. Required by the parser and used for concurrency control.

### --scim-token

SCIM provisioning bearer token.

**Accepted by:** `control`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | — |

**Runtime / audit note:** Literal SCIM provisioning credential accepted by control. Mutually exclusive with `--scim-token-file`, checked at runtime. Enabling SCIM also requires a directory administration backend.

### --scim-token-file

SCIM provisioning bearer token file.

**Accepted by:** `control`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `control` | string | unset | no | — | — |

**Runtime / audit note:** File containing the SCIM provisioning credential; surrounding whitespace is trimmed. Mutually exclusive with `--scim-token`. This is a credential input, not an output file.

### --sshd-binary

sshd executable used to validate configuration.

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |

**Runtime / audit note:** Executable used for sshd configuration validation. Resolved using platform defaults when omitted.

### --sshd-config-file

Main sshd configuration file (default: platform native).

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |

**Runtime / audit note:** Main sshd config path, selected from platform defaults when omitted.

### --sshd-fragment-file

Epithet-managed sshd fragment (default: platform native).

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |

**Runtime / audit note:** Path of the Epithet-managed sshd configuration fragment, selected from platform defaults or recovered enrollment when omitted.

### --state-dir

Declared meanings:

- `inventory *`: Shared root for inventory/ and directory/ storage (default: native system state directory).
- `directory *`: Root for directory storage.

**Accepted by:** `inventory *`, `directory *`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `inventory *` | string | unset | no | — | — |
| `directory *` | string | unset | no | — | — |

**Runtime / audit note:** Shared root convention: directory uses `<root>/directory/directory.db`; inventory uses `<root>/inventory`. Runtime defaults: Linux `/var/lib/epithet`; BSDs `/var/db/epithet`; macOS `/Library/Application Support/Epithet`; AIX/illumos/Solaris `/var/opt/epithet`; Windows `%ProgramData%/Epithet`. Static-only serving does not open managed storage. Administration subcommands inherit this option but do not use local service storage.

### --tls-ca-cert-file

Path to PEM file with trusted CA certificates.

**Accepted by:** All commands.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| All commands | string | unset | no | — | `EPITHET_TLS_CA_CERT` |

**Runtime / audit note:** PEM file providing trusted certificate authorities for outbound TLS. Unrelated to SSH CA public-key trust; accepted globally even where no outbound TLS is used.

### --token

Single-use enrollment token.

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |

**Runtime / audit note:** Single-use host enrollment credential sent by the enrolling host. Distinct from the SCIM provisioning credential. Cannot be combined with `--token-file`.

### --token-file

File containing a single-use enrollment token.

**Accepted by:** `host enroll`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `host enroll` | string | unset | no | — | — |

**Runtime / audit note:** File supplying the host enrollment credential instead of `--token`; surrounding whitespace is trimmed.

### --user

Remote user (%r).

**Accepted by:** `match`.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| `match` | string | unset | yes | `-r` | — |

**Runtime / audit note:** Target remote account, normally OpenSSH `%r`; not the local daemon/service account.

### --verbose

Increase verbosity (-v for debug, -vv for trace).

**Accepted by:** All commands.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| All commands | counter (repeatable) | `0` | no | `-v` | — |

**Runtime / audit note:** Repeatable counter: runtime logging is warning by default, `-v` enables info, and `-vv` or higher enables debug. Current CLI help incorrectly says debug/trace. Certificate issuance audit events have separate minimum-info handling.

### --version

Print version information.

**Accepted by:** All commands.

| Declared scope | Value | Parser default | Parser-required | Short | Environment |
| --- | --- | --- | --- | --- | --- |
| All commands | switch | off | no | `-V` | — |

**Runtime / audit note:** Prints build version information without running a service.

## Command inventory

`agent` defaults to `agent start`; `directory` defaults to `directory serve`; `inventory` defaults to `inventory serve`. `directory users` defaults to `directory users list`. These are parser-selected defaults, not separate implementations.

Command aliases:

- `agent`: `a`, `ag`.
- `agent identity`: `id`, `ide`, `iden`, `ident`.
- `agent inspect`: `in`, `ins`, `insp`.
- `inventory`: `i`, `inv`.
- `inventory list`: `l`, `li`, `lis`.
- `inventory show`: `s`, `sh`, `show`.
- `inventory edit`: `e`, `ed`, `edi`.
- `inventory approve`: `a`, `ap`, `app`.

Each row lists every accepted non-global long flag, including inherited flags. All rows additionally accept `--help`, `--version`, `--verbose`, `--log-file`, `--config`, `--insecure`, and `--tls-ca-cert-file`. Positional arguments are listed separately and are not flags.

| Command | Positional arguments | Accepted non-global flags |
| --- | --- | --- |
| `agent login` | — | `--agent-name`, `--ca`, `--ca-timeout`, `--ca-cooldown`, `--login-method`, `--broker-socket` |
| `agent logout` | — | `--agent-name`, `--ca`, `--ca-timeout`, `--ca-cooldown`, `--login-method`, `--broker-socket` |
| `agent identity` | — | `--agent-name`, `--ca`, `--ca-timeout`, `--ca-cooldown`, `--login-method`, `--broker-socket`, `--json` |
| `agent start` | `[<command> ...]` | `--agent-name`, `--ca`, `--ca-timeout`, `--ca-cooldown`, `--login-method` |
| `agent inspect` | `[<id>]` | `--agent-name`, `--ca`, `--ca-timeout`, `--ca-cooldown`, `--login-method`, `--broker-socket`, `--json`, `--compact`, `--expanded` |
| `agent kill` | `<agent-id>` | `--agent-name`, `--ca`, `--ca-timeout`, `--ca-cooldown`, `--login-method`, `--broker-socket` |
| `match` | — | `--host`, `--port`, `--user`, `--hash`, `--jump`, `--broker-socket` |
| `control` | — | `--listen`, `--control-key-file`, `--directory`, `--directory-backend`, `--inventory-backend`, `--oidc-identity-mode`, `--oidc-user-id-claim`, `--oidc-issuer`, `--oidc-client-id`, `--oidc-client-secret`, `--directory-admin-user`, `--directory-admin-group`, `--inventory-admin-user`, `--inventory-admin-group`, `--scim-token`, `--scim-token-file` |
| `ca` | — | `--control-public`, `--inventory`, `--directory`, `--oidc-identity-mode`, `--oidc-user-id-claim`, `--oidc-issuer`, `--oidc-client-id`, `--oidc-client-secret`, `--policy-file`, `--certificate-extension`, `--certificate-default-ttl`, `--ca-key-file`, `--listen` |
| `host enroll` | — | `--token`, `--token-file`, `--host-name`, `--ca`, `--principal-domain`, `--principal-domain-file`, `--ca-public-key-file`, `--principal-mode`, `--sshd-config-file`, `--sshd-fragment-file`, `--sshd-binary`, `--epithet-binary`, `--authorized-principals-command-user` |
| `host authorized-principals` | `<account>` | `--principal-domain-file` |
| `inventory serve` | — | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check` |
| `inventory list` | — | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check`, `--pending` |
| `inventory show` | `<host>` | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check` |
| `inventory edit` | `<host>` | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check` |
| `inventory approve` | `<host>` | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check` |
| `inventory remove` | `<host>` | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check` |
| `inventory token create` | — | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check`, `--expires-in`, `--quiet` |
| `inventory token list` | — | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check` |
| `inventory token revoke` | `<id>` | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check` |
| `inventory audit` | — | `--agent-name`, `--broker-socket`, `--inventory-mode`, `--state-dir`, `--listen`, `--control-public-key`, `--ca-public-key`, `--inventory-static-file`, `--principal-mode`, `--check` |
| `directory serve` | — | `--directory-mode`, `--directory-static-file`, `--state-dir`, `--listen`, `--ca-public-key`, `--control-public-key`, `--check`, `--agent-name`, `--broker-socket` |
| `directory users list` | — | `--directory-mode`, `--directory-static-file`, `--state-dir`, `--listen`, `--ca-public-key`, `--control-public-key`, `--check`, `--agent-name`, `--broker-socket`, `--json` |
| `directory groups list` | — | `--directory-mode`, `--directory-static-file`, `--state-dir`, `--listen`, `--ca-public-key`, `--control-public-key`, `--check`, `--agent-name`, `--broker-socket`, `--json` |
| `directory groups bind` | `<alias>`, `<group-id>` | `--directory-mode`, `--directory-static-file`, `--state-dir`, `--listen`, `--ca-public-key`, `--control-public-key`, `--check`, `--agent-name`, `--broker-socket`, `--revision` |
| `directory groups audit` | — | `--directory-mode`, `--directory-static-file`, `--state-dir`, `--listen`, `--ca-public-key`, `--control-public-key`, `--check`, `--agent-name`, `--broker-socket`, `--after`, `--limit` |
| `policy` | — | `--policy-file`, `--certificate-extension`, `--certificate-default-ttl`, `--check` |
| `router` (internal to `server`; command and local flags hidden) | — | `--listen`, `--ca-backend`, `--control-backend` |
| `server` | — | `--listen`, `--control-key-file`, `--ca-key-file`, `--policy-file`, `--directory-static-file`, `--inventory-static-file`, `--certificate-extension`, `--principal-mode` |

## Source pointers

- [CLI root and logging](../cmd/epithet/main.go), [config lookup](../cmd/epithet/config.go)
- [Combined launcher and child overrides](../cmd/epithet/server.go)
- [CA](../cmd/epithet/ca.go), [control](../cmd/epithet/control.go), [shared OIDC flags](../cmd/epithet/service_oidc.go), [router](../cmd/epithet/router.go)
- [Directory declarations](../cmd/epithet/directory.go), [directory serving](../cmd/epithet/directory_serve.go)
- [Inventory declarations and administration](../cmd/epithet/inventory.go), [inventory serving](../cmd/epithet/inventory_serve.go), [enrollment tokens](../cmd/epithet/inventory_token.go), [shared administration transport](../cmd/epithet/admin_client.go)
- [Agent](../cmd/epithet/agent.go), [login](../cmd/epithet/agent_login.go), [logout](../cmd/epithet/agent_logout.go), [identity](../cmd/epithet/agent_identity.go), [inspect](../cmd/epithet/agent_inspect.go), [kill](../cmd/epithet/agent_kill.go), [SSH match](../cmd/epithet/match.go)
- [Host enrollment](../cmd/epithet/host_enroll.go), [host SSHD setup](../cmd/epithet/host_enroll_sshd.go), [offline principals helper](../cmd/epithet/host.go)
- [Policy flags](../cmd/epithet/policy.go), [certificate defaults](../pkg/policyserver/policy_config.go), [native state paths](../pkg/config/state.go)
