package policy

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
