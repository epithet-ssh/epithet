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
	"sync/atomic"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Agent represents a read-only SSH agent that hands out a single,
// broker-issued credential. Epithet is not a general-purpose ssh-agent: the
// agent socket exists only so `ssh` can sign with the certificate the broker
// minted for this connection, so the keyring never accepts client-added
// keys - see UseCredential and readOnlyKeyring.
//
// Concurrency: Agent is safe for concurrent use. readOnlyKeyring holds its
// live credential behind an atomic.Pointer, so UseCredential can swap in a
// fresh credential while other goroutines are mid-List/Sign without a lock.
// The done channel and closeOnce provide safe shutdown coordination.
//
// Immutable after creation: agentSocketPath, log
// Self-synchronized: keyring (atomic swap)
// Protected by closeOnce: agentListener, done channel
// agentListener/startErr: written once by Serve() (which may run in its own
// goroutine), then guarded for readers by the ready channel - see WaitReady.
type Agent struct {
	keyring *readOnlyKeyring // Self-synchronized (atomic swap)
	log     *slog.Logger     // Immutable after New()

	agentSocketPath string // Immutable after New()
	agentListener   net.Listener

	// ready is closed once startAgentListener has run (successfully or not).
	// Callers that start Serve in a goroutine (e.g. broker.ensureAgent) must
	// receive from Ready (or call WaitReady) before touching agentListener
	// from another goroutine - e.g. before Close can safely run there.
	// Without this, the write to agentListener inside Serve's goroutine and
	// a later read in Close from a different goroutine have no
	// happens-before relationship at all: a genuine data race, not merely a
	// timing risk (caught by `go test -race`).
	ready    chan struct{}
	startErr error // Set before ready is closed; startAgentListener's result.

	done      chan struct{} // Closed once by closeOnce
	closeOnce sync.Once     // Protects Close() operations
}

// New creates a new SSH agent. This does not start listening - call Serve() to begin accepting connections.
// If agentSocketPath is empty, a temporary socket will be created when Serve() is called.
func New(logger *slog.Logger, agentSocketPath string) *Agent {
	return &Agent{
		agentSocketPath: agentSocketPath,
		keyring:         newReadOnlyKeyring(),
		log:             logger,
		ready:           make(chan struct{}),
		done:            make(chan struct{}),
	}
}

// Serve starts the agent listening on the configured socket and blocks until the context is cancelled.
// Returns an error if the listener cannot be started, otherwise returns ctx.Err() when shutdown completes.
func (a *Agent) Serve(ctx context.Context) error {
	err := a.startAgentListener()
	a.startErr = err
	close(a.ready) // See WaitReady: this is what makes agentListener safe to read from another goroutine.
	if err != nil {
		return err
	}

	// Serve connections in background
	go a.serve(ctx)

	// Block until context cancelled
	<-ctx.Done()
	a.Close()

	return ctx.Err()
}

// WaitReady blocks until Serve has started the agent's listener (or failed
// to) and returns any startup error. Callers that run Serve in a goroutine -
// and especially any that may later call Close from a different goroutine -
// must call this before doing either, so that the read of agentListener in
// Close happens-after the write in startAgentListener (see the Agent struct
// comment).
func (a *Agent) WaitReady() error {
	<-a.ready
	return a.startErr
}

// Credential contains the private key and certificate in PEM format
type Credential struct {
	PrivateKey  sshcert.RawPrivateKey
	Certificate sshcert.RawCertificate
}

// UseCredential replaces the agent's live credential with the provided one.
// The swap is atomic (see readOnlyKeyring): a client mid-List/Sign against
// the old credential is unaffected, and no lock/Close dance is needed since
// the old keyring is simply dropped, not mutated.
func (a *Agent) UseCredential(c Credential) error {
	if !a.Running() {
		return errors.New("agent has been stopped")
	}

	a.log.Debug("replacing credentials")
	return a.keyring.swap(c)
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

	a.log.Debug("new connection to agent", "socket", a.agentSocketPath)
	err := agent.ServeAgent(a.keyring, conn)
	if err != nil && err != io.EOF {
		a.log.Warn("error from ssh-agent", "error", err)
	}
}

// AgentSocketPath returns the path to the agent's Unix socket
func (a *Agent) AgentSocketPath() string {
	return a.agentSocketPath
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

// errReadOnly is returned by every mutating readOnlyKeyring method. Epithet
// hands this agent's socket to arbitrary child processes (ssh, scp, git);
// none of them may add, replace, or lock the one credential the broker
// issued, so every write path is refused rather than merely discouraged.
var errReadOnly = fmt.Errorf("epithet agent is read-only")

// readOnlyKeyring implements agent.ExtendedAgent as a read-only view over an
// in-memory keyring holding at most one credential. List/Sign/SignWithFlags/
// Signers delegate to the current inner keyring; swap replaces it atomically
// so UseCredential never needs to lock out concurrent Sign calls or unwind a
// partial list-add-remove sequence on error.
type readOnlyKeyring struct {
	inner atomic.Pointer[agent.Agent]
}

// newReadOnlyKeyring creates a readOnlyKeyring with an empty inner keyring,
// so List/Sign behave sanely before the first UseCredential call.
func newReadOnlyKeyring() *readOnlyKeyring {
	r := &readOnlyKeyring{}
	empty := agent.NewKeyring()
	r.inner.Store(&empty)
	return r
}

// swap parses the credential and installs it as the sole entry of a freshly
// built inner keyring, then atomically publishes it. Building the new
// keyring before publishing means a parse failure never disturbs the
// credential already being served.
func (r *readOnlyKeyring) swap(c Credential) error {
	cert, err := sshcert.Parse(c.Certificate)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	priv, err := ssh.ParseRawPrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("error parsing private key: %w", err)
	}

	fresh := agent.NewKeyring()
	if err := fresh.Add(agent.AddedKey{PrivateKey: priv, Certificate: cert}); err != nil {
		return fmt.Errorf("unable to add new credential: %w", err)
	}

	r.inner.Store(&fresh)
	return nil
}

func (r *readOnlyKeyring) current() agent.Agent {
	return *r.inner.Load()
}

func (r *readOnlyKeyring) List() ([]*agent.Key, error) {
	return r.current().List()
}

func (r *readOnlyKeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.current().Sign(key, data)
}

func (r *readOnlyKeyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if ext, ok := r.current().(agent.ExtendedAgent); ok {
		return ext.SignWithFlags(key, data, flags)
	}
	return r.current().Sign(key, data)
}

func (r *readOnlyKeyring) Signers() ([]ssh.Signer, error) {
	return r.current().Signers()
}

func (r *readOnlyKeyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	if ext, ok := r.current().(agent.ExtendedAgent); ok {
		return ext.Extension(extensionType, contents)
	}
	return nil, agent.ErrExtensionUnsupported
}

func (r *readOnlyKeyring) Add(key agent.AddedKey) error   { return errReadOnly }
func (r *readOnlyKeyring) Remove(key ssh.PublicKey) error { return errReadOnly }
func (r *readOnlyKeyring) RemoveAll() error               { return errReadOnly }
func (r *readOnlyKeyring) Lock(passphrase []byte) error   { return errReadOnly }
func (r *readOnlyKeyring) Unlock(passphrase []byte) error { return errReadOnly }
