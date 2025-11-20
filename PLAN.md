# Plan: Host → Users Mapping in Policy

## Problem

The broker's certificate matching only considers `HostPattern`, but principals map to users via `AuthorizedPrincipalsFile/Command`. A cert with principal "dev" might allow `arch@one.example.com` but not `root@two.example.com`.

**Current behavior**: Alice connects as `arch@server.example.com`, gets cert. Bob connects as `root@server.example.com`, reuses Alice's cert (wrong principals).

**Desired behavior**: Each (host pattern, user) combination gets its own certificate lookup.

---

## Changes

### 1. Update Policy Structure (`pkg/policy/policy.go`)

Replace `HostPattern string` with:

```go
type Policy struct {
    // Map of host pattern -> allowed users for that host
    // Example: {"*.example.com": ["arch", "deploy"], "prod-*": ["root"]}
    HostUsers map[string][]string `json:"hostUsers"`
}

// Matches checks if this policy matches the given connection's host AND user
func (p *Policy) Matches(conn Connection) bool {
    for pattern, users := range p.HostUsers {
        matched, err := filepath.Match(pattern, conn.RemoteHost)
        if err != nil || !matched {
            continue
        }
        // Host matches, check if user is in allowed list
        for _, u := range users {
            if u == conn.RemoteUser {
                return true
            }
        }
    }
    return false
}
```

### 2. Update CertificateStore (`pkg/broker/certs.go`)

**Key changes:**
- `Store()` always appends (no deduplication by pattern - policies can overlap)
- `Lookup()` returns first cert whose `HostUsers` mapping matches both host AND user
- Remove the "replace cert with same HostPattern" logic

```go
// Store adds a certificate. No deduplication - overlapping policies are fine.
func (cs *CertificateStore) Store(pc PolicyCert) {
    cs.lock.Lock()
    defer cs.lock.Unlock()
    cs.certs = append(cs.certs, pc)
}

// Lookup finds a valid certificate matching both host AND user.
func (cs *CertificateStore) Lookup(conn policy.Connection) (agent.Credential, bool) {
    cs.lock.Lock()
    defer cs.lock.Unlock()

    now := time.Now().Add(expiryBuffer)

    for i := 0; i < len(cs.certs); i++ {
        pc := cs.certs[i]

        // Check if policy matches host AND user
        if pc.Policy.Matches(conn) {
            if now.Before(pc.ExpiresAt) {
                return pc.Credential, true
            }
            // Expired, remove it
            cs.certs = append(cs.certs[:i], cs.certs[i+1:]...)
            i--
        }
    }

    return agent.Credential{}, false
}
```

### 3. Update policyserver Response (`pkg/policyserver/policyserver.go`)

The `Response` struct already embeds `policy.Policy`, so it automatically gets the new `HostUsers` field.

### 4. Update caserver Response (`pkg/caserver/caserver.go`)

The `CreateCertResponse` struct already embeds `policy.Policy`, so it automatically gets the new `HostUsers` field.

### 5. Update `epithet dev policy` (`cmd/epithet/dev.go`)

Return `HostUsers` map instead of `HostPattern`:

```go
return &policyserver.Response{
    CertParams: ca.CertParams{
        Identity:   e.identity,
        Names:      e.principals,
        Expiration: e.expiration,
        Extensions: map[string]string{
            "permit-agent-forwarding": "",
            "permit-pty":              "",
            "permit-user-rc":          "",
        },
    },
    Policy: policy.Policy{
        HostUsers: map[string][]string{
            "*": {conn.RemoteUser}, // Allow this user on all hosts
        },
    },
}, nil
```

### 6. Update policy server evaluator (`pkg/policyserver/evaluator/evaluator.go`)

Compute and return the `HostUsers` mapping based on user's tags and configured policies:

```go
func (e *Evaluator) Evaluate(token string, conn policy.Connection) (*policyserver.Response, error) {
    // ... existing token validation and user lookup ...

    // Compute HostUsers mapping: for each host pattern, which users can this identity access?
    hostUsers := e.computeHostUsers(userTags)

    // Check if the requested (host, user) is authorized
    if !e.isAuthorized(hostUsers, conn) {
        return nil, policyserver.Forbidden(...)
    }

    return &policyserver.Response{
        CertParams: ca.CertParams{
            Identity:   identity,
            Names:      principals,
            Expiration: expiration,
            Extensions: extensions,
        },
        Policy: policy.Policy{
            HostUsers: hostUsers,
        },
    }, nil
}

// computeHostUsers builds the mapping of host patterns to allowed users
// based on the user's tags and configured policies.
func (e *Evaluator) computeHostUsers(userTags []string) map[string][]string {
    hostUsers := make(map[string][]string)

    // From defaults (pattern "*")
    if e.config.Defaults != nil && e.config.Defaults.Allow != nil {
        var users []string
        for principal, allowedTags := range e.config.Defaults.Allow {
            if e.hasAnyTag(userTags, allowedTags) {
                users = append(users, principal)
            }
        }
        if len(users) > 0 {
            slices.Sort(users)
            hostUsers["*"] = users
        }
    }

    // From host-specific policies
    for hostname, hostPolicy := range e.config.Hosts {
        if hostPolicy.Allow != nil {
            var users []string
            for principal, allowedTags := range hostPolicy.Allow {
                if e.hasAnyTag(userTags, allowedTags) {
                    users = append(users, principal)
                }
            }
            if len(users) > 0 {
                slices.Sort(users)
                hostUsers[hostname] = users
            }
        }
    }

    return hostUsers
}

// isAuthorized checks if the connection is allowed by the hostUsers mapping
func (e *Evaluator) isAuthorized(hostUsers map[string][]string, conn policy.Connection) bool {
    for pattern, users := range hostUsers {
        matched, err := filepath.Match(pattern, conn.RemoteHost)
        if err != nil || !matched {
            continue
        }
        if slices.Contains(users, conn.RemoteUser) {
            return true
        }
    }
    return false
}
```

### 7. Update broker logging (`pkg/broker/broker.go:287`)

Change from:
```go
b.log.Debug("certificate obtained and stored", "host", input.Connection.RemoteHost, "policy", certResp.Policy.HostPattern)
```

To:
```go
b.log.Debug("certificate obtained and stored", "host", input.Connection.RemoteHost, "user", input.Connection.RemoteUser, "policy", certResp.Policy.HostUsers)
```

### 8. Update tests

**`pkg/policy/policy_test.go`** (new file or add to existing):
- Test `Matches()` with various host/user combinations
- Test multiple patterns in `HostUsers`
- Test user not in list for matching host
- Test wildcard patterns

**`pkg/broker/certs_test.go`**:
- Update all existing tests to use `HostUsers` instead of `HostPattern`
- Add test for same host, different users getting different certs
- Add test for overlapping policies (both can coexist)
- Remove `TestCertificateStore_UpdateExistingPattern` (no longer applicable)

**`pkg/policyserver/evaluator/evaluator_test.go`**:
- Test `computeHostUsers()` with various tag combinations
- Test `isAuthorized()` with different patterns

---

## Example Flow

1. Alice connects as `arch@one.example.com`:
   - No cert exists
   - CA returns `{hostUsers: {"*.example.com": ["arch", "deploy"], "one.example.com": ["root"]}}`
   - Cert stored, agent created

2. Bob connects as `root@one.example.com`:
   - Lookup: `{"*.example.com": ["arch", "deploy"], ...}` - host matches but user "root" not in list
   - Check next entry: `{"one.example.com": ["root"]}` - host and user match!
   - Wait, this is Alice's cert with Alice's principals - we need Bob's own cert
   - Lookup correctly fails (Alice's cert has principals for Alice, not Bob)
   - CA returns new cert with `{hostUsers: {"*.example.com": ["root"], "one.example.com": ["root"]}}`

3. Alice connects as `arch@two.example.com`:
   - Lookup: `{"*.example.com": ["arch", "deploy"]}` - matches!
   - Reuses existing cert (same principals work)

4. All certs coexist, expire naturally via cleanup goroutine

---

## Migration Notes

- **Wire format change**: `policy.Policy` JSON changes from `{"hostPattern": "..."}` to `{"hostUsers": {...}}`
- **Backward compatibility**: None needed (v2 is not yet released)
- **Policy server update**: Must be deployed with matching changes

---

## Implementation Order

1. `pkg/policy/policy.go` - Core type change
2. `pkg/policy/policy_test.go` - Tests for new Matches logic
3. `pkg/broker/certs.go` - Update Store/Lookup
4. `pkg/broker/certs_test.go` - Update tests
5. `cmd/epithet/dev.go` - Update dev policy server
6. `pkg/policyserver/evaluator/evaluator.go` - Compute HostUsers
7. `pkg/policyserver/evaluator/evaluator_test.go` - Test evaluator
8. `pkg/broker/broker.go` - Update logging
9. Integration test to verify end-to-end flow
