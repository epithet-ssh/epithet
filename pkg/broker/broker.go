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

	"github.com/epithet-ssh/epithet/pkg/agent"
)

type Broker struct {
	lock      sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
	log       slog.Logger

	brokerSocketPath string
	brokerListener   net.Listener
	auth             *Auth
	certStore        *CertificateStore
}

type MatchRequest struct {
	LocalHost      string
	LocalUser      string
	RemoteHost     string
	RemoteUser     string
	Port           uint
	ProxyJump      string
	ConnectionHash string
}

type MatchResponse struct {
	// Should the `Match exec` actually match?
	Allow bool

	// Error contains any error which should be reported to the user on stderr
	Error string
}

// New creates a new Broker instance. This does not start listening - call Serve() to begin accepting connections.
func New(log slog.Logger, socketPath string, authCommand string) *Broker {
	return &Broker{
		auth:             NewAuth(authCommand),
		certStore:        NewCertificateStore(),
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

// Match is invoked via rpc from `epithet match` invocations
func (b *Broker) Match(input MatchRequest, output *MatchResponse) error {
	// TODO: Implement the 5-step certificate validation workflow (epithet-18)
	// For now, just check if we have a valid certificate
	_, found := b.certStore.Lookup(input.RemoteHost)
	if found {
		b.log.Debug("found valid certificate for host", "host", input.RemoteHost)
	} else {
		b.log.Debug("no valid certificate found for host", "host", input.RemoteHost)
	}

	output.Allow = true
	return nil
}

// LookupCertificate finds a valid certificate for the given hostname.
// Returns the Credential and true if found and not expired, otherwise returns false.
func (b *Broker) LookupCertificate(hostname string) (agent.Credential, bool) {
	return b.certStore.Lookup(hostname)
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
