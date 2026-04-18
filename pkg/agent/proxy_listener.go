package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh/agent"
)

// ProxyListener accepts connections on a Unix socket and serves each with a
// ProxyAgent that proxies to an upstream agent. Each connection gets a fresh
// upstream dial (the SSH agent protocol is connection-scoped).
//
// The setup callback is called for each new ProxyAgent, allowing the caller
// to register extension handlers.
type ProxyListener struct {
	socketPath         string
	upstreamSocketPath string
	setup              func(*ProxyAgent)
	log                *slog.Logger

	listener  net.Listener
	ready     chan struct{} // Closed when listener is accepting connections.
	done      chan struct{}
	closeOnce sync.Once
}

// NewProxyListener creates a ProxyListener. Call Serve() to begin accepting connections.
func NewProxyListener(log *slog.Logger, socketPath, upstreamSocketPath string, setup func(*ProxyAgent)) *ProxyListener {
	return &ProxyListener{
		socketPath:         socketPath,
		upstreamSocketPath: upstreamSocketPath,
		setup:              setup,
		log:                log,
		ready:              make(chan struct{}),
		done:               make(chan struct{}),
	}
}

// Serve starts the listener and blocks until the context is cancelled.
// The ready channel is always closed before Serve returns, whether
// successfully or on error, so callers blocking on Ready() won't hang.
func (p *ProxyListener) Serve(ctx context.Context) error {
	os.Remove(p.socketPath)
	listener, err := net.Listen("unix", p.socketPath)
	if err != nil {
		close(p.ready)
		return err
	}
	if err := os.Chmod(p.socketPath, 0600); err != nil {
		listener.Close()
		close(p.ready)
		return err
	}
	p.listener = listener
	close(p.ready)

	go p.acceptLoop()

	<-ctx.Done()
	p.Close()
	return ctx.Err()
}

func (p *ProxyListener) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-p.done:
				return
			default:
				p.log.Warn("proxy listener accept error", "error", err)
				continue
			}
		}
		go p.serveConn(conn)
	}
}

func (p *ProxyListener) serveConn(conn net.Conn) {
	defer conn.Close()

	// Dial a fresh connection to the upstream agent for this client.
	upstreamConn, err := net.Dial("unix", p.upstreamSocketPath)
	if err != nil {
		p.log.Warn("failed to connect to upstream agent", "error", err)
		return
	}
	defer upstreamConn.Close()

	upstream := agent.NewClient(upstreamConn)
	extUpstream, ok := upstream.(agent.ExtendedAgent)
	if !ok {
		p.log.Warn("upstream agent does not support extensions")
		return
	}

	proxy := NewProxyAgent(extUpstream)
	p.setup(proxy)

	err = agent.ServeAgent(proxy, conn)
	if err != nil && err != io.EOF {
		p.log.Debug("proxy agent connection ended", "error", err)
	}
}

// Ready returns a channel that is closed when the listener is accepting connections.
func (p *ProxyListener) Ready() <-chan struct{} {
	return p.ready
}

// SocketPath returns the path to the proxy listener's Unix socket.
func (p *ProxyListener) SocketPath() string {
	return p.socketPath
}

// Close stops the listener and cleans up.
func (p *ProxyListener) Close() {
	p.closeOnce.Do(func() {
		if p.listener != nil {
			p.listener.Close()
		}
		close(p.done)
	})
}
