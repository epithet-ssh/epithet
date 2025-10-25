package policy

import "path/filepath"

// Connection represents the complete tuple of SSH connection parameters.
// This matches the parameters available in OpenSSH Match exec via %C hash:
// local hostname (%l), remote hostname (%h), port (%p), remote user (%r), and ProxyJump (%j).
type Connection struct {
	LocalHost  string `json:"localHost"`
	LocalUser  string `json:"localUser"`
	RemoteHost string `json:"remoteHost"`
	RemoteUser string `json:"remoteUser"`
	Port       uint   `json:"port"`
	ProxyJump  string `json:"proxyJump"`
}

// Policy represents the policy rules for certificate usage
type Policy struct {
	HostPattern string `json:"hostPattern"` // Glob pattern for matching hostnames (e.g., "*.example.com")
}

// Matches checks if this policy's pattern matches the given connection's remote hostname
func (p *Policy) Matches(conn Connection) bool {
	matched, err := filepath.Match(p.HostPattern, conn.RemoteHost)
	if err != nil {
		// Invalid pattern, no match
		return false
	}
	return matched
}
