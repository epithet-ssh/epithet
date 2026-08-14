package policy

// ConnectionHash is the OpenSSH %C hash value that uniquely identifies a connection.
// This is computed by OpenSSH from the connection parameters (local host, remote host, port, user, ProxyJump).
type ConnectionHash string

// Connection represents the SSH connection parameters epithet actually uses.
// These come from OpenSSH's Match exec via %h/%p/%r/%j; local hostname (%l)
// was transmitted here too but never read anywhere downstream, so it was
// dropped (spec §13) along with the os.Hostname() call that populated it.
// The Hash field contains the %C hash value computed by OpenSSH from the
// full connection tuple (including local host), so it still uniquely
// identifies the connection even without LocalHost as a separate field.
type Connection struct {
	RemoteHost string         `json:"remoteHost"`
	RemoteUser string         `json:"remoteUser"`
	Port       uint           `json:"port"`
	ProxyJump  string         `json:"proxyJump"`
	Hash       ConnectionHash `json:"hash"` // %C - hash of connection tuple
}
