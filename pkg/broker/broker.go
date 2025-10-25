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
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/policy"
)

// agentEntry tracks a running agent and when its certificate expires
type agentEntry struct {
	agent     *agent.Agent
	expiresAt time.Time
}

type Broker struct {
	lock      sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
	log       slog.Logger

	brokerSocketPath string
	brokerListener   net.Listener
	auth             *Auth
	certStore        *CertificateStore
	agents           map[string]agentEntry // connectionHash → agent
}

// New creates a new Broker instance. This does not start listening - call Serve() to begin accepting connections.
func New(log slog.Logger, socketPath string, authCommand string) *Broker {
	return &Broker{
		auth:             NewAuth(authCommand),
		certStore:        NewCertificateStore(),
		agents:           make(map[string]agentEntry),
		brokerSocketPath: socketPath,
		done:             make(chan struct{}),
		log:              log,
	}
}

// Serve starts the broker listening on the configured socket and blocks until the context is cancelled.
// Returns an error if the listener cannot be started, otherwise returns ctx.Err() when shutdown completes.
func (b *Broker) Serve(ctx context.Context) error {
	if err := b.startBrokerListener(); err != nil {
		return fmt.Errorf("unable to start broker socket: %w", err)
	}

	// Serve connections in background
	go b.serve(ctx)

	// Block until context cancelled
	<-ctx.Done()
	b.Close()

	return ctx.Err()
}

func (b *Broker) startBrokerListener() error {
	_ = os.Remove(b.brokerSocketPath) // Remove socket if it exists
	brokerListener, err := net.Listen("unix", b.brokerSocketPath)
	if err != nil {
		return fmt.Errorf("unable to start broker listener: %w", err)
	}

	b.brokerListener = brokerListener
	return nil
}

type MatchRequest struct {
	Connection policy.Connection
}

type MatchResponse struct {
	// Should the `Match exec` actually match?
	Allow bool

	// Error contains any error which should be reported to the user on stderr
	Error string
}

// Match is invoked via rpc from `epithet match` invocations
func (b *Broker) Match(input MatchRequest, output *MatchResponse) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	// Check if agent already exists for this connection hash
	if entry, exists := b.agents[input.Connection.Hash]; exists {
		// Check if agent's certificate is still valid (with buffer)
		if time.Now().Add(expiryBuffer).Before(entry.expiresAt) {
			b.log.Debug("found existing valid agent", "hash", input.Connection.Hash, "expires", entry.expiresAt)
			output.Allow = true
			return nil
		}
		// Agent expired - clean it up
		b.log.Debug("cleaning up expired agent", "hash", input.Connection.Hash, "expired", entry.expiresAt)
		entry.agent.Close()
		delete(b.agents, input.Connection.Hash)
	}

	// Check if we have an auth token, if not authenticate
	token := b.auth.Token()
	if token == "" {
		b.log.Debug("no auth token, authenticating")
		var err error
		token, err = b.auth.Run(nil) // TODO(epithet-41): pass connection details for template rendering
		if err != nil {
			b.log.Error("authentication failed", "error", err)
			output.Allow = false
			output.Error = fmt.Sprintf("authentication failed: %v", err)
			return nil
		}
		b.log.Debug("authentication successful")
	}

	// TODO(epithet-18): Check cert store for valid cert
	// TODO(epithet-21): If no cert, request from CA
	// TODO(epithet-25): Create agent with credential

	// For now, just return false (no agent available)
	b.log.Debug("no valid agent found for connection", "hash", input.Connection.Hash, "host", input.Connection.RemoteHost)
	output.Allow = false
	return nil
}

// LookupCertificate finds a valid certificate for the given connection.
// Returns the Credential and true if found and not expired, otherwise returns false.
func (b *Broker) LookupCertificate(conn policy.Connection) (agent.Credential, bool) {
	return b.certStore.Lookup(conn)
}

// StoreCertificate adds or updates a certificate for a given policy pattern.
func (b *Broker) StoreCertificate(pc PolicyCert) {
	b.certStore.Store(pc)
}

func (b *Broker) serve(ctx context.Context) {
	server := rpc.NewServer()
	server.Register(b)
	for {
		// Check if context is done
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := b.brokerListener.Accept()
		if err != nil {
			// Check if error is from listener being closed
			if errors.Is(err, net.ErrClosed) {
				// Listener closed, exit gracefully
				return
			}
			// Check context again before logging
			select {
			case <-ctx.Done():
				return
			default:
				b.log.Warn("Unable to accept connection", "error", err)
				continue
			}
		}
		go func() {
			defer conn.Close()
			server.ServeConn(conn)
		}()
	}
}

func (b *Broker) Done() <-chan struct{} {
	return b.done
}

func (b *Broker) Close() {
	b.closeOnce.Do(func() {
		_ = b.brokerListener.Close()

		// Close all agents
		b.lock.Lock()
		for hash, entry := range b.agents {
			b.log.Debug("closing agent on broker shutdown", "hash", hash)
			entry.agent.Close()
		}
		b.agents = make(map[string]agentEntry)
		b.lock.Unlock()

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
