package agent

import (
	"encoding/json"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh/agent"
)

// ProbeUpstream connects to the agent socket and sends epithet-hello.
// Returns the hello response if the agent supports epithet extensions,
// or nil if it's a vanilla ssh-agent.
func ProbeUpstream(socketPath string) (*HelloResponse, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream agent: %w", err)
	}
	defer conn.Close()

	client := agent.NewClient(conn)
	extClient, ok := client.(agent.ExtendedAgent)
	if !ok {
		return nil, nil
	}

	resp, err := extClient.Extension(ExtensionHello, nil)
	if err != nil {
		// ErrExtensionUnsupported means it's a vanilla ssh-agent.
		if err == agent.ErrExtensionUnsupported {
			return nil, nil
		}
		return nil, fmt.Errorf("hello extension failed: %w", err)
	}

	// Strip the SSH_AGENT_SUCCESS byte.
	if len(resp) > 0 && resp[0] == agentSuccess {
		resp = resp[1:]
	}

	var hello HelloResponse
	if err := json.Unmarshal(resp, &hello); err != nil {
		return nil, fmt.Errorf("failed to parse hello response: %w", err)
	}

	return &hello, nil
}

// RequestAuth sends an epithet-auth extension request to the upstream agent.
// The upstream runs its own auth plugin with its own state — only the token
// is returned.
func RequestAuth(socketPath string) (string, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("failed to connect to upstream agent: %w", err)
	}
	defer conn.Close()

	client := agent.NewClient(conn)
	extClient, ok := client.(agent.ExtendedAgent)
	if !ok {
		return "", fmt.Errorf("upstream agent does not support extensions")
	}

	resp, err := extClient.Extension(ExtensionAuth, nil)
	if err != nil {
		return "", fmt.Errorf("auth extension failed: %w", err)
	}

	// Strip the SSH_AGENT_SUCCESS byte.
	if len(resp) > 0 && resp[0] == agentSuccess {
		resp = resp[1:]
	}

	var authResp AuthResponse
	if err := json.Unmarshal(resp, &authResp); err != nil {
		return "", fmt.Errorf("failed to parse auth response: %w", err)
	}

	if authResp.Token == "" {
		return "", fmt.Errorf("upstream returned empty token")
	}

	return authResp.Token, nil
}
