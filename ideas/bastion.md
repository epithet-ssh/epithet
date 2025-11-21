# Using epithet with SSH Jump Hosts

> **Note**: This document was extracted from the `bastion` branch (Oct 2025) for future reference. None of this is currently implemented.

## Overview

This document explores how epithet can work with SSH jump hosts (bastions) to provide certificate-based authentication for both the jump connection and the final target connection, while maintaining end-to-end encryption.

## Background: Jump Host Session Recording Challenge

### Initial Question: Can tlog record sessions through jump hosts?

**Short answer: No, not with ProxyJump.**

When using SSH ProxyJump (`ssh -J jumphost target`):
- ProxyJump is TCP port forwarding, not a shell session
- The jumphost's sshd creates a forwarding channel without invoking a login shell
- The actual PTY (pseudo-terminal) and shell session happen entirely on the final destination
- tlog on the jumphost only captures direct login sessions, not forwarded connections

### How Warpgate Does Session Recording

Warpgate takes a completely different approach:

**Connection model:**
```
Client SSH → Warpgate SSH Server → Warpgate SSH Client → Target Server
   (encrypted)    (decrypted)           (encrypted)
```

**User connects:**
```bash
ssh user:target-name@warpgate.example.com -p 2222
```

**How it works:**
1. Warpgate runs its own SSH server
2. Client establishes SSH connection to Warpgate
3. **Warpgate terminates the SSH connection (decrypts it)**
4. Warpgate authenticates the user locally
5. Warpgate parses the username to extract the target
6. Warpgate establishes a separate SSH connection to the target
7. Warpgate bridges the two connections
8. **Because Warpgate decrypts both sides, it can see and record all terminal I/O**

**Key difference from ProxyJump:**
- ProxyJump: Pure TCP forwarding, never decrypts traffic, cannot record
- Warpgate: SSH man-in-the-middle proxy, terminates and re-establishes connections, can record everything

## What Jump Hosts Can See with ProxyJump

### Information Available to Jump Host

According to **RFC 4254 Section 7.2** (TCP/IP Forwarding Channels), the `direct-tcpip` channel request includes:

**Jump host KNOWS:**
- Jump username (who authenticated to the jump host)
- Destination hostname (string - domain name or IP)
- Destination port (uint32)
- Originator IP address (client's IP)
- Originator port (client's source port)
- Timestamp

**Jump host does NOT know:**
- Remote username (encrypted in the SSH session)
- Remote auth method (encrypted)
- Terminal session content (encrypted end-to-end)
- Commands being run (encrypted)

### Two Separate Authentications

ProxyJump involves **two separate SSH authentications:**

1. **Client → Jump Host**: User authenticates (e.g., alice@jumphost)
2. **Client → Target** (through tunnel): User authenticates (e.g., root@target)

**Example:**
```bash
ssh -J alice@jumphost root@production-server
```

Jump host logs show:
- User: alice
- Action: Opened direct-tcpip channel
- Destination: production-server:22

Jump host does NOT see that alice is connecting as `root`.

## SSH Agent Forwarding

### Basic Agent Forwarding

SSH has built-in agent forwarding that can work with epithet:

```bash
ssh -A -J jumphost target
```

**What happens:**
1. Client's epithet agent has certificate for target
2. Client connects to jump host
3. Agent is forwarded through to jump host
4. Jump host's outbound SSH to target uses the forwarded agent
5. Target sees the epithet certificate from client's agent

**Security concern:** Traditional agent forwarding allows the jump host to use your agent for ANY connection while you're connected.

### SSH Agent Restrictions (OpenSSH 8.9+)

OpenSSH 8.9+ introduced **destination constraints** for agent keys:

```bash
# Add key with destination constraints
ssh-add -h "target1.example.org" -h "target2.example.org" ~/.ssh/id_ed25519

# Now even when forwarded, this key can ONLY be used for target1 or target2
ssh -A jumphost
```

**How it works:**
- Uses hostkeys to cryptographically identify permitted destinations
- Agent refuses signature requests unless they match permitted paths
- Even a compromised jump host cannot misuse the key
- Perfect complement to epithet's short-lived certificates

## epithet with Jump Hosts Solution

### The Approach: ProxyJump + Agent Forwarding + epithet

**Connection command:**
```bash
ssh -A -J alice@jumphost postgres@production-db
```

**SSH config:**
```ssh_config
Match exec "epithet match --host %h --port %p --user %r --hash %C --jump %j"
    IdentityAgent ~/.epithet/sockets/%C
    ForwardAgent yes
```

### SSH Token Expansion

The `%j` token provides full ProxyJump context in format: `[user@]host[:port][,next_jump...]`

The `%C` token is a hash of `%l%h%p%r%j`:
- %l: Local hostname
- %h: Remote hostname
- %p: Remote port
- %r: Remote username
- %j: ProxyJump string (including user if specified)

Since %C includes %j, agent sockets are automatically unique per jump path:
- `ssh postgres@db` (no jump) → one %C
- `ssh -J jumphost postgres@db` → different %C
- `ssh -J alice@jumphost postgres@db` → different %C
- `ssh -J other-jump postgres@db` → yet another %C

### epithet Match Flow

**When epithet match is called:**

1. Parse `%j` to extract:
   - `jump_host` (required)
   - `jump_user` (optional, defaults to current user)
   - `jump_port` (optional, defaults to 22)

2. Request certificate from CA with full context:
```json
{
  "target_host": "production-db",
  "target_port": 22,
  "target_user": "postgres",
  "jump_host": "jumphost.example.com",
  "jump_user": "alice",
  "jump_port": 22
}
```

3. CA policy server evaluates: "Can current_user use alice@jumphost to reach postgres@production-db?"

4. CA issues certificate with appropriate principals and expiration

5. epithet loads certificate into agent at `~/.epithet/sockets/%C`

6. SSH connects with agent forwarding enabled

7. Both connections authenticated with epithet certificates

### What You Get

**Audit trail (via CA requests):**
- WHO: authenticated user (via auth token to CA)
- WHERE: target host/port/user
- VIA: jump_host/jump_port/jump_user
- WHEN: timestamp

**Security properties:**
- Short-lived certificates (2-10 minutes)
- Policy enforcement at CA (can evaluate jump topology)
- End-to-end encryption maintained (jump host can't see session content)
- Jump host can log: who connected + destination (from direct-tcpip channel)
- Agent restrictions can limit forwarded keys to specific destinations

**Infrastructure:**
- Standard SSH (no custom client software)
- Simple jump host configuration
- Works with existing SSH tooling

### What You Don't Get (vs Warpgate-style)

- Session recording/playback
- Real-time session monitoring
- Ability to terminate sessions from jump host
- Visibility into remote username from jump host perspective

But you keep standard SSH, simpler infrastructure, and stronger encryption properties.

## Terminology

Use OpenSSH terminology consistently:
- **Jump host**: The intermediate host (not "bastion" in code/APIs)
- **jump_user, jump_host, jump_port**: Connection parameters for the jump
- **Bastion**: One specific use case for jump hosts (hardened access control)

Jump hosts can be used for many purposes:
- Bastions (hardened access control points)
- NAT traversal (reaching hosts behind firewalls)
- Network segmentation (accessing different network zones)
- Development (local port forwards, SOCKS proxies)
- Multi-hop (chaining through multiple networks)

epithet should stay agnostic about *why* someone is using a jump host and just provide the policy server with the connection topology.

## Go SSH Server Support for Forwarded Agents

The `golang.org/x/crypto/ssh` and `golang.org/x/crypto/ssh/agent` packages provide complete support for SSH servers to work with forwarded agents.

### How It Works on the Server Side

When a client connects with agent forwarding enabled:

1. **Client sends request:** `"auth-agent-req@openssh.com"`
   - Server detects this and tracks that agent forwarding is requested
   - Reply with `req.Reply(true, nil)` if `req.WantReply == true`

2. **Server needs agent for outbound connection:**
   - Open SSH channel back to client: `"auth-agent@openssh.com"`
   - Wrap channel in agent client: `ag := agent.NewClient(channel)`
   - Use agent signers: `ssh.PublicKeysCallback(ag.Signers)`

### Two Implementation Patterns

#### Pattern 1: Direct Channel (Bastion/Proxy Use)

```go
// When making outbound SSH connection from server
agentChannel, _, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
if err == nil {
    ag := agent.NewClient(agentChannel)
    outboundConfig.Auth = []ssh.AuthMethod{
        ssh.PublicKeysCallback(ag.Signers),
    }
}
```

This pattern is used when the server acts as a proxy and needs to authenticate outbound connections using the client's forwarded agent.

#### Pattern 2: Unix Socket (Shell Session Use)

```go
// Create Unix socket
listener, _ := net.Listen("unix", "/tmp/agent.sock")

// Set environment variable in session
env = append(env, "SSH_AUTH_SOCK=/tmp/agent.sock")

// Proxy connections: socket ↔ SSH channel
go func() {
    for {
        conn, _ := listener.Accept()
        channel, _, _ := sshConn.OpenChannel("auth-agent@openssh.com", nil)
        go io.Copy(channel, conn)
        go io.Copy(conn, channel)
    }
}()
```

This pattern is used when providing a shell session that needs access to the agent (e.g., for nested SSH commands).

### For epithet Integration

If building a Warpgate-style bastion with epithet, the server would:

1. Accept client connection (possibly using epithet cert)
2. Detect `"auth-agent-req@openssh.com"` from client
3. When connecting to target, open `"auth-agent@openssh.com"` channel back to client
4. Use `agent.NewClient(channel)` to get signers
5. Target gets client's epithet certificate via forwarded agent

The Go SSH library provides all necessary primitives for this implementation.

## Audit Architecture Comparison

### Warpgate-Style (Terminating Proxy)

**Audit location: Bastion**

**What you can audit:**
- Complete session recording (full terminal I/O in asciicast format)
- Real-time session monitoring
- Remote username (seen in plaintext during connection setup)
- All commands executed
- Ability to terminate sessions

**Requirements:**
- Custom bastion software (SSH man-in-the-middle)
- Terminates and re-establishes SSH connections
- Storage for session recordings
- Web UI for playback/monitoring

**Trade-offs:**
- ✅ Complete audit trail at single location
- ✅ Real-time visibility and control
- ❌ Breaks end-to-end encryption
- ❌ Complex critical infrastructure component
- ❌ Bastion compromise exposes all session content

### ProxyJump + Agent Forwarding (E2E Encrypted)

**Audit locations: CA + Jump Host + Targets**

**At the CA (certificate request time):**
- WHO: authenticated user (via auth token)
- WHERE: target_host, target_port, target_user
- VIA: jump_host, jump_user, jump_port
- WHEN: timestamp
- ALLOWED?: policy decision with full topology context

**At the jump host (sshd logs, DEBUG level):**
- WHO: jump_user (authenticated to jump host)
- WHERE: destination host:port from direct-tcpip channel
- WHEN: timestamp
- But NOT: remote username, session content

**At the target host (standard sshd logs):**
- WHO: remote username + certificate principals
- FROM: source IP (jump host)
- WHEN: timestamp
- WHAT: Can enable session recording (e.g., tlog) here if needed

**Trade-offs:**
- ✅ Centralized policy enforcement at CA
- ✅ Distributed audit (each component logs what it sees)
- ✅ End-to-end encryption maintained
- ✅ Standard SSH, simpler infrastructure
- ✅ Jump host compromise doesn't expose session content
- ❌ No centralized session recording
- ❌ No real-time session monitoring from jump host
- ❌ Requires correlation across multiple log sources

### Key Insight: Centralized Policy, Distributed Audit

With epithet + ProxyJump approach:

**Centralized at CA:**
- Policy enforcement with complete connection topology
- Single source of truth for "who can access what via which path"
- Unified audit log of all access attempts and decisions

**Distributed at endpoints:**
- Each component logs what it authentically knows
- Jump host logs who went where (but not session content)
- Targets log who accessed them and can record sessions locally
- Session recordings only where compliance requires them (tlog on sensitive targets)

**Benefits:**
- Most security/audit benefits without complexity of terminating proxies
- Stronger crypto properties (E2E encryption)
- Simpler infrastructure (standard SSH everywhere)
- Selective session recording (only on targets that need it)
- Defense in depth (compromise of jump host doesn't expose sessions)

## Future Consideration: Terminating Proxy

If audit requirements change and session recording becomes necessary, epithet could support a Warpgate-style terminating proxy:

**Architecture:**
```
Client → Proxy (terminates SSH) → Target
         ↓
    - Uses epithet cert for auth
    - Sees plaintext session
    - Records everything
    - Re-establishes SSH to target
```

**Trade-offs:**
- ✅ Complete audit trail with session recording
- ✅ Policy enforcement at proxy
- ❌ Breaks end-to-end encryption
- ❌ Proxy becomes critical/complex component
- ❌ Requires custom proxy software

This approach can be revisited later if needed, but the ProxyJump + agent forwarding approach provides good security and auditability while keeping standard SSH semantics.
