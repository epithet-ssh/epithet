package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/rpc"
	"os"
	"sync"
)

type Broker struct {
	lock      sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
	log       slog.Logger

	brokerSocketPath string
	brokerListener   net.Listener
	auth             *Auth
}

type MatchRequest struct {
	LocalHost      string
	LocalUser      string
	RemoteHost     string
	RemoteUser     string
	Port           string
	ProxyJump      string
	ConnectionHash string
}

type MatchResponse struct {
	// Should the `Match exec` actually match?
	Allow bool

	// Error contains any error which should be reported to the user on stderr
	Error string
}

func New(ctx context.Context, log slog.Logger, socketPath string, authCommand string) (*Broker, error) {
	b := Broker{
		auth:             NewAuth(authCommand),
		brokerSocketPath: socketPath,
		done:             make(chan struct{}),
		log:              log,
	}

	err := b.startBrokerListener()
	if err != nil {
		return nil, fmt.Errorf("Unable to start broker socket: %w", err)
	}

	context.AfterFunc(ctx, func() {
		b.Close()
	})
	return &b, nil
}

func (b *Broker) startBrokerListener() error {
	_ = os.Remove(b.brokerSocketPath) // Remove socket if it exists
	brokerListener, err := net.Listen("unix", b.brokerSocketPath)
	if err != nil {
		return fmt.Errorf("unable to start broker listener: %w", err)
	}

	b.brokerListener = brokerListener
	go b.listenAndServe()
	return nil
}

// Match is invoked via rpc from `epithet match` invocations
func (b *Broker) Match(input MatchRequest, output *MatchResponse) error {
	output.Allow = true
	return nil
}

func (b *Broker) listenAndServe() {
	server := rpc.NewServer()
	server.Register(b)
	for {
		conn, err := b.brokerListener.Accept()
		if err != nil {
			// Check if error is from listener being closed
			if errors.Is(err, net.ErrClosed) {
				// Listener closed, exit gracefully
				return
			}
			// Log other errors only if still running
			if b.Running() {
				b.log.Warn("Unable to accept connection", "error", err)
				continue
			}
			return
		}
		defer conn.Close()
		go server.ServeConn(conn)
	}
}

func (b *Broker) Done() <-chan struct{} {
	return b.done
}

func (b *Broker) Close() {
	b.closeOnce.Do(func() {
		_ = b.brokerListener.Close()
		close(b.done)
	})
}

func (b *Broker) Running() bool {
	select {
	case <-b.Done():
		return false
	default:
		return true
	}
}
