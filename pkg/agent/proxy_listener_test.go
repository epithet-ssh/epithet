package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// startVanillaAgent starts a plain ssh-agent keyring on a Unix socket.
func startVanillaAgent(t *testing.T) (string, func()) {
	t.Helper()

	f, err := os.CreateTemp("", "vanilla-agent.*")
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

	return sockPath, func() {
		listener.Close()
		os.Remove(sockPath)
	}
}

func TestProxyListenerEndToEnd(t *testing.T) {
	// Set up a vanilla upstream agent.
	upstreamSock, cleanupUpstream := startVanillaAgent(t)
	defer cleanupUpstream()

	// Create proxy listener that adds epithet extensions.
	proxySock := tempSocketPath(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	authCalled := false
	setup := func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(0))
		p.RegisterExtension(ExtensionAuth, AuthHandler(func() (string, error) {
			authCalled = true
			return "proxy-listener-token", nil
		}))
	}
	proxy := NewProxyListener(logger, proxySock, upstreamSock, setup)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go proxy.Serve(ctx)
	waitForSocket(t, proxySock)

	// Connect to the proxy and test extensions.
	conn, err := net.Dial("unix", proxySock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := agent.NewClient(conn).(agent.ExtendedAgent)

	// Test hello.
	resp, err := client.Extension(ExtensionHello, nil)
	if err != nil {
		t.Fatalf("hello failed: %v", err)
	}
	var hello HelloResponse
	if err := json.Unmarshal(stripSuccessByte(t, resp), &hello); err != nil {
		t.Fatalf("unmarshal hello: %v", err)
	}
	if hello.ProtocolVersion != 1 {
		t.Errorf("expected protocol_version=1, got %d", hello.ProtocolVersion)
	}

	// Test auth.
	resp, err = client.Extension(ExtensionAuth, nil)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}
	var authResp AuthResponse
	if err := json.Unmarshal(stripSuccessByte(t, resp), &authResp); err != nil {
		t.Fatalf("unmarshal auth: %v", err)
	}
	if authResp.Token != "proxy-listener-token" {
		t.Errorf("expected 'proxy-listener-token', got %q", authResp.Token)
	}
	if !authCalled {
		t.Error("auth handler was not called")
	}

	// Test standard agent ops pass through to upstream.
	keys, err := client.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestProxyListenerMultipleConnections(t *testing.T) {
	// Each connection should get its own upstream dial.
	upstreamSock, cleanupUpstream := startVanillaAgent(t)
	defer cleanupUpstream()

	proxySock := tempSocketPath(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	callCount := 0
	setup := func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(0))
		p.RegisterExtension(ExtensionAuth, AuthHandler(func() (string, error) {
			callCount++
			return "token", nil
		}))
	}
	proxy := NewProxyListener(logger, proxySock, upstreamSock, setup)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go proxy.Serve(ctx)
	waitForSocket(t, proxySock)

	// Make two independent connections.
	for i := range 3 {
		conn, err := net.Dial("unix", proxySock)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		client := agent.NewClient(conn).(agent.ExtendedAgent)
		_, err = client.Extension(ExtensionAuth, nil)
		if err != nil {
			t.Fatalf("connection %d auth: %v", i, err)
		}
		conn.Close()
	}

	if callCount != 3 {
		t.Errorf("expected 3 auth calls, got %d", callCount)
	}
}

func TestMultiHopChain(t *testing.T) {
	// Simulate: laptop → shell1 → shell2
	// Each hop has its own proxy listener wrapping the previous.
	// An auth request on shell2 should traverse back to the laptop.

	// Laptop: vanilla agent + proxy with auth handler (the origin).
	laptopUpstream, cleanupLaptop := startVanillaAgent(t)
	defer cleanupLaptop()

	laptopProxy := tempSocketPath(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	laptopAuthCalled := false
	laptopSetup := func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(0))
		p.RegisterExtension(ExtensionAuth, AuthHandler(func() (string, error) {
			laptopAuthCalled = true
			return "laptop-origin-token", nil
		}))
	}
	laptopListener := NewProxyListener(logger, laptopProxy, laptopUpstream, laptopSetup)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go laptopListener.Serve(ctx)
	waitForSocket(t, laptopProxy)

	// Verify laptop probe shows depth 0.
	hello, err := ProbeUpstream(laptopProxy)
	if err != nil {
		t.Fatalf("probe laptop: %v", err)
	}
	if hello == nil {
		t.Fatal("expected epithet agent at laptop, got nil")
	}
	if hello.ChainDepth != 0 {
		t.Errorf("laptop depth: expected 0, got %d", hello.ChainDepth)
	}

	// Shell1: proxy wrapping laptop, with depth 1.
	// Auth requests are forwarded to laptop via RequestAuth.
	shell1Proxy := tempSocketPath(t)
	shell1Setup := func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(1))
		p.RegisterExtension(ExtensionAuth, AuthHandler(func() (string, error) {
			// Shell1 proxies auth to laptop.
			return RequestAuth(laptopProxy)
		}))
	}
	shell1Listener := NewProxyListener(logger, shell1Proxy, laptopProxy, shell1Setup)

	go shell1Listener.Serve(ctx)
	waitForSocket(t, shell1Proxy)

	// Verify shell1 probe shows depth 1.
	hello, err = ProbeUpstream(shell1Proxy)
	if err != nil {
		t.Fatalf("probe shell1: %v", err)
	}
	if hello.ChainDepth != 1 {
		t.Errorf("shell1 depth: expected 1, got %d", hello.ChainDepth)
	}

	// Shell2: proxy wrapping shell1, with depth 2.
	shell2Proxy := tempSocketPath(t)
	shell2Setup := func(p *ProxyAgent) {
		p.RegisterExtension(ExtensionHello, HelloHandler(2))
		p.RegisterExtension(ExtensionAuth, AuthHandler(func() (string, error) {
			// Shell2 proxies auth to shell1.
			return RequestAuth(shell1Proxy)
		}))
	}
	shell2Listener := NewProxyListener(logger, shell2Proxy, shell1Proxy, shell2Setup)

	go shell2Listener.Serve(ctx)
	waitForSocket(t, shell2Proxy)

	// Verify shell2 probe shows depth 2.
	hello, err = ProbeUpstream(shell2Proxy)
	if err != nil {
		t.Fatalf("probe shell2: %v", err)
	}
	if hello.ChainDepth != 2 {
		t.Errorf("shell2 depth: expected 2, got %d", hello.ChainDepth)
	}

	// Request auth from shell2 — should chain all the way back to laptop.
	token, err := RequestAuth(shell2Proxy)
	if err != nil {
		t.Fatalf("multi-hop auth: %v", err)
	}
	if token != "laptop-origin-token" {
		t.Errorf("expected 'laptop-origin-token', got %q", token)
	}
	if !laptopAuthCalled {
		t.Error("laptop auth handler was never called — chain is broken")
	}
}

// tempSocketPath returns a unique temporary socket path.
func tempSocketPath(t *testing.T) string {
	t.Helper()
	// Use /tmp for short paths (macOS 104-byte socket path limit).
	f, err := os.CreateTemp("/tmp", "ep-test.*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	os.Remove(path)
	t.Cleanup(func() { os.Remove(path) })
	return path
}

// waitForSocket polls until the Unix socket is accepting connections.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", path)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s never became available", path)
}
