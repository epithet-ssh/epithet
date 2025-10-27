package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errAgentStopped = errors.New("agent has been stopped")

// Agent represents an SSH agent that manages certificates.
//
// Concurrency: Agent is safe for concurrent use. The keyring (golang.org/x/crypto/ssh/agent)
// has internal synchronization and can be safely accessed from multiple goroutines.
// The done channel and closeOnce provide safe shutdown coordination.
//
// Immutable after creation: agentSocketPath, publicKey, privateKey, caClient, log
// Protected by internal sync: keyring (uses its own locking)
// Protected by closeOnce: agentListener, done channel
type Agent struct {
	keyring  agent.Agent // Thread-safe (has internal locking)
	caClient *caclient.Client
	log      *slog.Logger // Immutable after New()

	agentSocketPath string // Immutable after New()
	agentListener   net.Listener

	publicKey  sshcert.RawPublicKey  // Immutable after New()
	privateKey sshcert.RawPrivateKey // Immutable after New()

	done      chan struct{} // Closed once by closeOnce
	closeOnce sync.Once     // Protects Close() operations
}

// New creates a new SSH agent. This does not start listening - call Serve() to begin accepting connections.
// If agentSocketPath is empty, a temporary socket will be created when Serve() is called.
func New(logger *slog.Logger, caClient *caclient.Client, agentSocketPath string) (*Agent, error) {
	pub, priv, err := sshcert.GenerateKeys()
	if err != nil {
		return nil, err
	}

	return &Agent{
		agentSocketPath: agentSocketPath,
		keyring:         agent.NewKeyring(),
		caClient:        caClient,
		log:             logger,
		publicKey:       pub,
		privateKey:      priv,
		done:            make(chan struct{}),
	}, nil
}

// Serve starts the agent listening on the configured socket and blocks until the context is cancelled.
// Returns an error if the listener cannot be started, otherwise returns ctx.Err() when shutdown completes.
func (a *Agent) Serve(ctx context.Context) error {
	if err := a.startAgentListener(); err != nil {
		return err
	}

	// Serve connections in background
	go a.serve(ctx)

	// Block until context cancelled
	<-ctx.Done()
	a.Close()

	return ctx.Err()
}

// Credential contains the private key and certificate in PEM format
type Credential struct {
	PrivateKey  sshcert.RawPrivateKey
	Certificate sshcert.RawCertificate
}

// UseCredential replaces the current credentials in the agent with the provided credential
func (a *Agent) UseCredential(c Credential) error {
	if !a.Running() {
		return errAgentStopped
	}

	a.log.Debug("replacing credentials")
	oldKeys, err := a.keyring.List()
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to list current credentials: %w", err)
	}

	cert, err := sshcert.Parse(c.Certificate)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	priv, err := ssh.ParseRawPrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("error parsing private key: %w", err)
	}
	err = a.keyring.Add(agent.AddedKey{
		PrivateKey:  priv,
		Certificate: cert,
	})
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to add new credential: %w", err)
	}

	for _, k := range oldKeys {
		err = a.keyring.Remove(k)
		if err != nil {
			a.Close()
			return fmt.Errorf("unable to remove old credential: %w", err)
		}
	}
	return nil
}

func (a *Agent) startAgentListener() error {
	if a.agentSocketPath == "" {
		f, err := os.CreateTemp("", "epithet-agent.*")
		if err != nil {
			a.Close()
			return fmt.Errorf("unable to create agent socket: %w", err)
		}
		a.agentSocketPath = f.Name()
		f.Close()
		os.Remove(f.Name())
	}

	os.Remove(a.agentSocketPath) // Remove socket if it exists
	agentListener, err := net.Listen("unix", a.agentSocketPath)
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to listen on %s: %w", a.agentSocketPath, err)
	}

	err = os.Chmod(a.agentSocketPath, 0600)
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to set permissions on agent socket: %w", err)
	}
	a.agentListener = agentListener
	return nil
}

func (a *Agent) serve(ctx context.Context) {
	for {
		// Check if context is done
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := a.agentListener.Accept()
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			// Check if error is from listener being closed
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Check context again before logging
			select {
			case <-ctx.Done():
				return
			default:
				a.log.Warn("error on accept from SSH_AUTH_SOCK listener", "error", err)
				continue
			}
		}
		go a.serveAgent(conn)
	}
}

func (a *Agent) serveAgent(conn net.Conn) {
	defer conn.Close()

	a.log.Debug("new connection to agent")
	err := agent.ServeAgent(a.keyring, conn)
	if err != nil && err != io.EOF {
		a.log.Warn("error from ssh-agent", "error", err)
	}
}

// AgentSocketPath returns the path to the agent's Unix socket
func (a *Agent) AgentSocketPath() string {
	return a.agentSocketPath
}

// IsAgentStopped returns true if the error indicates that the agent has been stopped
func IsAgentStopped(err error) bool {
	return errors.Is(err, errAgentStopped)
}

// Running returns true if the agent is currently running and accepting connections
func (a *Agent) Running() bool {
	select {
	case <-a.Done():
		return false
	default:
		return true
	}
}

// Done returns a channel that is closed when the agent has been closed and cleanup is complete.
// This can be used with select statements or waitgroups to know when the agent is fully stopped.
func (a *Agent) Done() <-chan struct{} {
	return a.done
}

// Close stops the agent and cleans up resources. Safe to call multiple times.
func (a *Agent) Close() {
	a.closeOnce.Do(func() {
		if a.agentListener != nil {
			_ = a.agentListener.Close() // Ignore error
		}
		close(a.done)
	})
}
