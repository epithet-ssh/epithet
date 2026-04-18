package agent

import (
	"net"
	"os"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

// startProxyServerSocket creates a ProxyAgent over a real Unix socket, returning
// the socket path and a cleanup function. Used to test upstream client functions.
func startProxyServerSocket(t *testing.T, setup func(*ProxyAgent)) (string, func()) {
	t.Helper()

	upstream := agent.NewKeyring()

	f, err := os.CreateTemp("", "upstream-test.*")
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

	cleanup := func() {
		listener.Close()
		os.Remove(sockPath)
	}

	return sockPath, cleanup
}

func TestProbeUpstreamEpithet(t *testing.T) {
	sockPath, cleanup := startProxyServerSocket(t, func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(2))
	})
	defer cleanup()

	hello, err := ProbeUpstream(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if hello == nil {
		t.Fatal("expected hello response, got nil")
	}
	if hello.ProtocolVersion != 1 {
		t.Errorf("expected protocol_version=1, got %d", hello.ProtocolVersion)
	}
	if hello.ChainDepth != 2 {
		t.Errorf("expected chain_depth=2, got %d", hello.ChainDepth)
	}
}

func TestProbeUpstreamVanillaAgent(t *testing.T) {
	// Serve a plain keyring (no extensions registered) — behaves like a vanilla ssh-agent.
	f, err := os.CreateTemp("", "vanilla-test.*")
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
	defer func() {
		listener.Close()
		os.Remove(sockPath)
	}()

	keyring := agent.NewKeyring()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				agent.ServeAgent(keyring, c)
			}(conn)
		}
	}()

	hello, err := ProbeUpstream(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if hello != nil {
		t.Errorf("expected nil for vanilla agent, got %+v", hello)
	}
}

func TestProbeUpstreamBadSocket(t *testing.T) {
	_, err := ProbeUpstream("/nonexistent/socket.sock")
	if err == nil {
		t.Fatal("expected error for bad socket path")
	}
}

func TestRequestAuth(t *testing.T) {
	sockPath, cleanup := startProxyServerSocket(t, func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionAuth, AuthHandler(func() (string, error) {
			return "upstream-token-456", nil
		}))
	})
	defer cleanup()

	token, err := RequestAuth(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if token != "upstream-token-456" {
		t.Errorf("expected 'upstream-token-456', got %q", token)
	}
}

func TestRequestAuthNoExtensionSupport(t *testing.T) {
	// Serve a proxy with no auth handler registered — upstream returns ErrExtensionUnsupported.
	sockPath, cleanup := startProxyServerSocket(t, func(p *ProxyAgent) {
		// No extensions registered.
	})
	defer cleanup()

	_, err := RequestAuth(sockPath)
	if err == nil {
		t.Fatal("expected error when auth extension not supported")
	}
}
