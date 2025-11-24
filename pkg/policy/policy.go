package policy

import (
	"path/filepath"
	"slices"
)

// ConnectionHash is the OpenSSH %C hash value that uniquely identifies a connection.
// This is computed by OpenSSH from the connection parameters (local host, remote host, port, user, ProxyJump).
type ConnectionHash string

// Connection represents the complete tuple of SSH connection parameters.
// This matches the parameters available in OpenSSH Match exec via %C hash:
// local hostname (%l), remote hostname (%h), port (%p), remote user (%r), and ProxyJump (%j).
// The Hash field contains the %C hash value computed by OpenSSH from these parameters.
type Connection struct {
	LocalHost  string         `json:"localHost"`
	RemoteHost string         `json:"remoteHost"`
	RemoteUser string         `json:"remoteUser"`
	Port       uint           `json:"port"`
	ProxyJump  string         `json:"proxyJump"`
	Hash       ConnectionHash `json:"hash"` // %C - hash of connection tuple
}

// Policy represents the policy rules for certificate usage
type Policy struct {
	// HostUsers maps host patterns to allowed users for that host
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
		if slices.Contains(users, conn.RemoteUser) {
			return true
		}
	}
	return false
}
