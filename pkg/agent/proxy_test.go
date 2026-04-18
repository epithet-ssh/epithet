package agent

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

// startProxyServer creates a ProxyAgent over a real Unix socket, returning the
// client-side ExtendedAgent and a cleanup function.
func startProxyServer(t *testing.T, setup func(*ProxyAgent)) (agent.ExtendedAgent, func()) {
	t.Helper()

	upstream := agent.NewKeyring()

	f, err := os.CreateTemp("", "proxy-test.*")
	if err != nil {
		t.Fatal(err)
	}
	sockPath := f.Name()
	f.Close()
	os.Remove(sockPath)

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				proxy := NewProxyAgent(upstream.(agent.ExtendedAgent))
				setup(proxy)
				agent.ServeAgent(proxy, c)
			}(conn)
		}
	}()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		listener.Close()
		os.Remove(sockPath)
		t.Fatal(err)
	}

	client := agent.NewClient(conn)

	cleanup := func() {
		conn.Close()
		listener.Close()
		os.Remove(sockPath)
	}

	return client.(agent.ExtendedAgent), cleanup
}

// stripSuccessByte removes the leading SSH_AGENT_SUCCESS byte from an
// extension response. The client returns the raw wire buffer which starts
// with the type byte.
func stripSuccessByte(t *testing.T, resp []byte) []byte {
	t.Helper()
	if len(resp) == 0 {
		t.Fatal("empty response")
	}
	if resp[0] != agentSuccess {
		t.Fatalf("expected first byte %d (SSH_AGENT_SUCCESS), got %d", agentSuccess, resp[0])
	}
	return resp[1:]
}

func TestHelloHandler(t *testing.T) {
	client, cleanup := startProxyServer(t, func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(0))
	})
	defer cleanup()

	resp, err := client.Extension(ExtensionHello, nil)
	if err != nil {
		t.Fatal(err)
	}

	var hello HelloResponse
	if err := json.Unmarshal(stripSuccessByte(t, resp), &hello); err != nil {
		t.Fatalf("failed to unmarshal hello response: %v", err)
	}

	if hello.ProtocolVersion != 1 {
		t.Errorf("expected protocol_version=1, got %d", hello.ProtocolVersion)
	}
	if hello.ChainDepth != 0 {
		t.Errorf("expected chain_depth=0, got %d", hello.ChainDepth)
	}
}

func TestHelloHandlerChainDepth(t *testing.T) {
	client, cleanup := startProxyServer(t, func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(3))
	})
	defer cleanup()

	resp, err := client.Extension(ExtensionHello, nil)
	if err != nil {
		t.Fatal(err)
	}

	var hello HelloResponse
	if err := json.Unmarshal(stripSuccessByte(t, resp), &hello); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if hello.ChainDepth != 3 {
		t.Errorf("expected chain_depth=3, got %d", hello.ChainDepth)
	}
}

func TestAuthHandler(t *testing.T) {
	called := false
	client, cleanup := startProxyServer(t, func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionAuth, AuthHandler(func() (string, error) {
			called = true
			return "test-token-123", nil
		}))
	})
	defer cleanup()

	resp, err := client.Extension(ExtensionAuth, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !called {
		t.Error("authenticate function was not called")
	}

	var authResp AuthResponse
	if err := json.Unmarshal(stripSuccessByte(t, resp), &authResp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if authResp.Token != "test-token-123" {
		t.Errorf("expected token 'test-token-123', got %q", authResp.Token)
	}
}

func TestAuthHandlerError(t *testing.T) {
	client, cleanup := startProxyServer(t, func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionAuth, AuthHandler(func() (string, error) {
			return "", errors.New("user cancelled")
		}))
	})
	defer cleanup()

	_, err := client.Extension(ExtensionAuth, nil)
	if err == nil {
		t.Fatal("expected error from failed auth, got nil")
	}
}

func TestStandardOpsPassthrough(t *testing.T) {
	client, cleanup := startProxyServer(t, func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(0))
	})
	defer cleanup()

	// List should work (empty keyring).
	keys, err := client.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestUnregisteredExtensionForwardedToUpstream(t *testing.T) {
	// The upstream keyring's Extension returns ErrExtensionUnsupported,
	// which ServeAgent translates to SSH_AGENT_FAILURE.
	client, cleanup := startProxyServer(t, func(p *ProxyAgent) {
		// Register nothing — all extensions forward to upstream.
	})
	defer cleanup()

	_, err := client.Extension("unknown@example.com", nil)
	if err == nil {
		t.Fatal("expected error for unknown extension, got nil")
	}
}

func TestCustomExtensionHandler(t *testing.T) {
	client, cleanup := startProxyServer(t, func(p *ProxyAgent) {
		p.RegisterExtension("custom@example.com", func(contents []byte) ([]byte, error) {
			return []byte("custom-response"), nil
		})
	})
	defer cleanup()

	resp, err := client.Extension("custom@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	payload := stripSuccessByte(t, resp)
	if string(payload) != "custom-response" {
		t.Errorf("expected 'custom-response', got %q", string(payload))
	}
}

func TestDirectProxyAgentExtension(t *testing.T) {
	// Test the ProxyAgent directly without going through the socket,
	// verifying the raw wire format (includes success byte).
	upstream := agent.NewKeyring()
	proxy := NewProxyAgent(upstream.(agent.ExtendedAgent))
	proxy.RegisterExtension(ExtensionHello, HelloHandler(0))

	resp, err := proxy.Extension(ExtensionHello, nil)
	if err != nil {
		t.Fatal(err)
	}

	// First byte should be SSH_AGENT_SUCCESS (6).
	if len(resp) == 0 {
		t.Fatal("empty response")
	}
	if resp[0] != agentSuccess {
		t.Errorf("expected first byte %d (SSH_AGENT_SUCCESS), got %d", agentSuccess, resp[0])
	}

	// Rest should be valid JSON.
	var hello HelloResponse
	if err := json.Unmarshal(resp[1:], &hello); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if hello.ProtocolVersion != 1 {
		t.Errorf("expected protocol_version=1, got %d", hello.ProtocolVersion)
	}
}

