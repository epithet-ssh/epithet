package agent

import (
	"encoding/json"
	"fmt"
)

// Extension type constants follow the OpenSSH vendor extension naming convention.
const (
	ExtensionHello = "epithet-hello@epithet.dev"
	ExtensionAuth  = "epithet-auth@epithet.dev"
)

// HelloResponse is returned by the epithet-hello extension.
type HelloResponse struct {
	ProtocolVersion int `json:"protocol_version"`
	ChainDepth      int `json:"chain_depth"`
}

// AuthResponse is returned by the epithet-auth extension.
type AuthResponse struct {
	Token string `json:"token"`
}

// HelloHandler returns an ExtensionHandler for epithet-hello@epithet.dev.
func HelloHandler(depth int) ExtensionHandler {
	return func(_ []byte) ([]byte, error) {
		return json.Marshal(HelloResponse{
			ProtocolVersion: 1,
			ChainDepth:      depth,
		})
	}
}

// AuthHandler returns an ExtensionHandler for epithet-auth@epithet.dev.
// The authenticate function is called to obtain a token — typically wired
// to the broker's auth flow.
//
// Security: the returned token is a bearer credential that transits the SSH
// agent forwarding channel. Any host in the forwarding chain (i.e., the
// remote sshd process) can observe the token. This is the same trust model
// as standard SSH agent forwarding — the remote host can use the forwarded
// agent to sign challenges on the user's behalf. Users should only forward
// agents to hosts they trust, same as with ssh-agent -A.
func AuthHandler(authenticate func() (string, error)) ExtensionHandler {
	return func(_ []byte) ([]byte, error) {
		token, err := authenticate()
		if err != nil {
			return nil, fmt.Errorf("auth failed: %w", err)
		}
		return json.Marshal(AuthResponse{Token: token})
	}
}
