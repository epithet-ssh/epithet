---
title: mechanism to tunnel auth to remote agent
id: gszy91dg
created: 2025-12-01T18:36:44.286521Z
updated: 2025-12-01T21:53:04.529307Z
author: Brian McCallister
priority: medium
---

It would eb good to have a mechanism to tunnel auth protocol stuff to a remote host. 

Imagine this scenario:

Endpoint: laptop1
Server: shell1
Servers: host1, host2, host3

User is physically present on laptop1, but wants to be able to run epithet on shell1, say because the CA is only available on an internal network, so calls to the CA need to happen from shell1 instead of laptop1.

We can only pop a browser on laptop1, though, so the auth plugin needs to run on laptop1, but controlled by epithet on shell1.

Possible approaches:

- have a special agent that can run on the endpoint which tunnels auth stuff over an agent protocol extension
- spin up an ssh stream against an epithet remote from laptop1 to shell1. This would be like vscode remoting stuff, maybe
- Can we do either of these via a jumphost setup? 

Either way, I think we are going to wind up with a special agent version that runs on the endpoint, which is not going to play nicely with the way ssh likes to tunnel things for jumphsost.

This is goign to require some thinking

Worked up a possible design:

# Epithet Chained Agent Authentication

## Problem Statement

Users need to SSH into remote hosts where the CA is only reachable from that remote network. The authentication plugins (hardware keys, Tauri dialogs, biometrics, etc.) must run on the user's local machine, but certificate issuance must happen from the remote host.

The standard SSH agent forwarding mechanism provides a path for the remote host to request signatures from the local agent, but we need something more: the ability for a remote epithet instance to trigger auth plugin execution on the local machine and receive a certificate back.

## Background: SSH Agent Protocol Constraints

The SSH agent protocol is strictly client-initiated request/response:

- Client sends a request
- Agent sends exactly one response
- Agent never sends unsolicited messages

The extension mechanism (`SSH_AGENTC_EXTENSION`, 0x1b) follows this same pattern. This means "callbacks" must be modeled as requests from the remote side that the local side handles.

Importantly, when SSH forwards an agent socket to a remote host, anything with access to that socket can send requests through it. This gives us a bidirectional RPC channel disguised as agent forwarding.

## Proposed Design

### Session Initialization

The user invokes epithet as a wrapper around their shell on the remote host:

```bash
# In .bashrc, .profile, or manually:
epithet agent fish
```

The `epithet agent` command:

1. Checks for `SSH_AUTH_SOCK` in the inherited environment
2. Probes that socket to detect if it's an epithet agent (vs vanilla ssh-agent)
3. If epithet, stashes the socket path as `upstream_auth_sock`
4. Creates its own agent socket
5. Sets `SSH_AUTH_SOCK` to the new socket
6. Execs the child process (fish, bash, etc.)

The remote epithet instance now:
- Acts as the SSH agent for the session
- Has a backchannel to the local epithet via the upstream socket

### Protocol Extensions

#### Discovery: `epithet-hello@epithet.dev`

Used to probe whether a socket is an epithet agent.

Request:
```
byte    SSH_AGENTC_EXTENSION (0x1b)
string  "epithet-hello@epithet.dev"
uint32  protocol_version
```

Response (epithet agent):
```
byte    SSH_AGENT_SUCCESS
uint32  protocol_version
string  capabilities_json
```

Response (vanilla ssh-agent):
```
byte    SSH_AGENT_EXTENSION_FAILURE
```
or
```
byte    SSH_AGENT_FAILURE
```

Capabilities JSON could include:
```json
{
  "reachable_cas": ["ca.example.com"],
  "auth_plugins": ["fido2", "tauri-dialog"],
  "chain_depth": 0,
  "principal_constraints": ["user@example.com"]
}
```

#### Certificate Issuance: `epithet-issue-cert@epithet.dev`

Request:
```
byte    SSH_AGENTC_EXTENSION (0x1b)
string  "epithet-issue-cert@epithet.dev"
string  request_json
```

Request JSON:
```json
{
  "public_key": "ssh-ed25519 AAAA...",
  "principals": ["deploy"],
  "validity_seconds": 300,
  "ca_hint": "prod-ca.internal"
}
```

Response (success):
```
byte    SSH_AGENT_SUCCESS
string  certificate  # OpenSSH certificate format
```

Response (auth required / in progress):
```
byte    SSH_AGENT_SUCCESS
string  status_json
```

Status JSON for pending auth:
```json
{
  "status": "pending",
  "auth_type": "fido2",
  "message": "Touch your security key..."
}
```

The remote caller would poll or the request could block until auth completes (simpler).

#### Optional: Auth Status/Cancel

If we want to support cancellation or status updates:

```
byte    SSH_AGENTC_EXTENSION (0x1b)
string  "epithet-auth-status@epithet.dev"
string  request_id
```

## Data Flow Example

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Local Machine  │   SSH   │  Remote Host    │         │  Internal CA    │
│                 │ ─────── │                 │         │  (restricted)   │
│  epithet agent  │         │  epithet agent  │         │                 │
│  + auth plugins │         │  + CA client    │         │                 │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         │ ◄─────────────────────────│                           │
         │   epithet-hello           │                           │
         │ ─────────────────────────►│                           │
         │   capabilities            │                           │
         │                           │                           │
         │                           │  (user runs ssh to        │
         │                           │   another internal host)  │
         │                           │                           │
         │ ◄─────────────────────────│                           │
         │   epithet-issue-cert      │                           │
         │   {principals: [deploy]}  │                           │
         │                           │                           │
         │   [local auth plugin      │                           │
         │    runs: FIDO2 touch]     │                           │
         │                           │                           │
         │ ─────────────────────────►│                           │
         │   {certificate: ...}      │                           │
         │                           │ ─────────────────────────►│
         │                           │   CA signs cert           │
         │                           │ ◄─────────────────────────│
         │                           │   signed cert             │
         │                           │                           │
         │                           │  (cert used for auth)     │
```

Wait, I drew that wrong. Let me reconsider the flow:

If the CA is only reachable from the remote host, then:
1. Remote epithet talks to CA
2. But auth plugins run locally
3. So remote epithet asks local epithet to "prove" the user is present
4. Local epithet runs auth plugin, returns... what? A signature? An attestation?

There are two models here:

### Model A: Local Issues Cert, Remote Just Needs It

Local epithet is the CA (or talks to a CA reachable from local). Remote just needs a cert and asks for one. This is what the above protocol describes.

### Model B: Remote Issues Cert, Local Provides Auth Attestation

Remote epithet talks to a CA only reachable from remote. But it needs proof the user is present at the local machine. Local epithet runs auth plugin and returns an attestation/signature that remote epithet includes in its CA request.

```
Remote -> Local: epithet-auth-challenge (nonce)
Local:          runs auth plugin, signs nonce
Local -> Remote: epithet-auth-response (signature, attestation)
Remote -> CA:   cert request + user attestation
CA -> Remote:   signed certificate
```

This model is more complex but handles the "CA only reachable from remote" case.

### Model C: Hybrid

Local epithet can issue short-lived "auth tokens" that remote epithet presents to its CA. The CA trusts these tokens as proof of user presence.

## Open Questions

1. **Which model fits the use case?** Need to clarify where the CA lives and what proof it needs.

2. **Multi-hop chaining**: If there are multiple hops (local -> bastion -> internal), each epithet could chain to its upstream. The protocol should support this (chain_depth in capabilities).

3. **Socket lifecycle**: When the SSH session ends, the upstream socket goes away. Remote epithet needs to handle this gracefully.

4. **Multiple sessions**: If a user has multiple SSH sessions from the same local machine to the same remote, each has its own forwarded socket. Remote epithet instances are per-session (child of the shell), so this works naturally.

5. **Security considerations**: 
   - The forwarded socket is only as secure as the SSH connection
   - A compromised remote host could spam auth requests (rate limiting?)
   - Should local epithet require user confirmation for remote cert requests?

## Implementation Notes

### Detecting Epithet vs Vanilla Agent

```rust
fn probe_upstream(socket_path: &Path) -> Result<Option<EpithetCapabilities>> {
    let stream = UnixStream::connect(socket_path)?;
    
    // Send epithet-hello extension
    let request = build_extension_request("epithet-hello@epithet.dev", &HelloRequest {
        protocol_version: 1,
    });
    stream.write_all(&request)?;
    
    // Read response
    let response = read_agent_response(&stream)?;
    
    match response.message_type {
        SSH_AGENT_SUCCESS => {
            let caps: EpithetCapabilities = parse_response(&response.payload)?;
            Ok(Some(caps))
        }
        SSH_AGENT_FAILURE | SSH_AGENT_EXTENSION_FAILURE => {
            // Vanilla agent, no epithet support
            Ok(None)
        }
        _ => Err(Error::UnexpectedResponse),
    }
}
```

### Agent Wrapper Mode

```rust
fn agent_wrapper(shell: &str) -> Result<()> {
    // Check for upstream
    let upstream = env::var("SSH_AUTH_SOCK").ok()
        .and_then(|path| probe_upstream(Path::new(&path)).ok().flatten());
    
    // Create our socket
    let socket_path = create_agent_socket()?;
    
    // Start agent with upstream reference
    let agent = EpithetAgent::new(upstream);
    let _handle = agent.serve(&socket_path)?;
    
    // Exec shell with our socket
    env::set_var("SSH_AUTH_SOCK", &socket_path);
    let err = exec::execvp(shell, &[shell]);
    Err(err.into())
}
```

## Related Reading

- [OpenSSH agent-restrict.html](https://www.openssh.org/agent-restrict.html) - destination constraints design
- OpenSSH `PROTOCOL.agent` - wire format for agent protocol
- [draft-miller-ssh-agent](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent) - IETF agent protocol spec

---
## Log

### 2025-12-01T18:36:44Z Brian McCallister

Created task.

### 2025-12-01T21:52:12Z Brian McCallister

Updated description with possible design