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
func AuthHandler(authenticate func() (string, error)) ExtensionHandler {
	return func(_ []byte) ([]byte, error) {
		token, err := authenticate()
		if err != nil {
			return nil, fmt.Errorf("auth failed: %w", err)
		}
		return json.Marshal(AuthResponse{Token: token})
	}
}
