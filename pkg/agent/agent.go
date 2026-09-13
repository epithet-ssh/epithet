package agent

import (
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
// Start returns a fully initialized agent; its owner must call Close to stop
// it. All methods are safe for concurrent use. The lifecycle mutex serializes
// credential replacement and connection admission with shutdown; signing reads
// the keyring's atomic snapshot without taking that mutex.
type Agent struct {
	keyring *readOnlyKeyring
	log     *slog.Logger

	// Immutable after Start.
	agentSocketPath string
	agentListener   net.Listener

	mu          sync.Mutex // Protects stopped, connections, and credential writes.
	stopped     bool
	connections map[net.Conn]struct{}

	serving   sync.WaitGroup // Accept loop and all admitted connections.
	done      chan struct{}  // Closed after all serving goroutines have exited.
	closeOnce sync.Once
}

// Start installs the initial credential and starts serving a read-only SSH
// agent. On success the socket is listening with mode 0600 and the credential
// is ready for use. On failure no listener or serving goroutine remains.
// An empty socket path selects a temporary socket. The caller owns the returned
// agent and must Close it; its lifetime is independent of any match request.
func Start(logger *slog.Logger, agentSocketPath string, credential Credential) (*Agent, error) {
	keyring := newReadOnlyKeyring()
	if err := keyring.swap(credential); err != nil {
		return nil, err
	}
	if agentSocketPath == "" {
		f, err := os.CreateTemp("", "epithet-agent.*")
		if err != nil {
			return nil, fmt.Errorf("unable to create agent socket: %w", err)
		}
		agentSocketPath = f.Name()
		if err := f.Close(); err != nil {
			os.Remove(agentSocketPath)
			return nil, fmt.Errorf("unable to close temporary agent socket file: %w", err)
		}
	}

	os.Remove(agentSocketPath) // Remove socket if it exists.
	listener, err := net.Listen("unix", agentSocketPath)
	if err != nil {
		return nil, fmt.Errorf("unable to listen on %s: %w", agentSocketPath, err)
	}
	if err := os.Chmod(agentSocketPath, 0600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("unable to set permissions on agent socket: %w", err)
	}
	a := &Agent{
		agentSocketPath: agentSocketPath,
		agentListener:   listener,
		keyring:         keyring,
		log:             logger,
		connections:     make(map[net.Conn]struct{}),
		done:            make(chan struct{}),
	}
	a.serving.Add(1)
	go a.serve()
	return a, nil
}

// Credential contains the private key and certificate in PEM format
type Credential struct {
	PrivateKey  sshcert.RawPrivateKey
	Certificate sshcert.RawCertificate
}

// UseCredential replaces the agent's live credential with the provided one.
// The swap is atomic (see readOnlyKeyring): a client mid-List/Sign against
// the old credential is unaffected, and no lock/Close dance is needed since
// the old keyring is simply dropped, not mutated. Invalid credentials leave
// the current credential intact. Replacement after shutdown begins fails.
func (a *Agent) UseCredential(c Credential) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped {
		return errors.New("agent has been stopped")
	}

	a.log.Debug("replacing credentials")
	return a.keyring.swap(c)
}

func (a *Agent) serve() {
	defer a.serving.Done()
	for {
		conn, err := a.agentListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			a.log.Warn("error on accept from SSH_AUTH_SOCK listener", "error", err)
			continue
		}
		a.mu.Lock()
		if a.stopped {
			a.mu.Unlock()
			conn.Close()
			return
		}
		a.connections[conn] = struct{}{}
		a.serving.Add(1)
		a.mu.Unlock()
		go a.serveAgent(conn)
	}
}

func (a *Agent) serveAgent(conn net.Conn) {
	defer func() {
		conn.Close()
		a.mu.Lock()
		delete(a.connections, conn)
		a.mu.Unlock()
		a.serving.Done()
	}()

	a.log.Debug("new connection to agent", "socket", a.agentSocketPath)
	err := agent.ServeAgent(a.keyring, conn)
	if err != nil && err != io.EOF && !errors.Is(err, net.ErrClosed) {
		a.log.Warn("error from ssh-agent", "error", err)
	}
}

// AgentSocketPath returns the path to the agent's Unix socket
func (a *Agent) AgentSocketPath() string {
	return a.agentSocketPath
}

// Certificate returns the raw certificate currently served by this agent.
// An empty value means the agent has no live credential.
func (a *Agent) Certificate() sshcert.RawCertificate {
	return a.keyring.certificate()
}

// Running reports whether the agent is still accepting work. It becomes false
// when shutdown begins; Done signals when cleanup is complete.
func (a *Agent) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.stopped
}

// Done returns a channel that is closed when the agent has been closed and cleanup is complete.
// This can be used with select statements or waitgroups to know when the agent is fully stopped.
func (a *Agent) Done() <-chan struct{} {
	return a.done
}

// Close discards the credential, closes the listener and existing agent
// connections, and waits for all serving goroutines to exit. Concurrent and
// repeated calls wait for the same completed shutdown. Established SSH sessions
// are unaffected; operations still requiring this agent can no longer sign.
func (a *Agent) Close() {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.stopped = true
		a.keyring.clear()
		a.agentListener.Close()
		for conn := range a.connections {
			conn.Close()
		}
		a.mu.Unlock()

		// Admission and replacement are now disabled. The accept loop is
		// counted from Start, so even an accepted-but-unregistered connection
		// must be closed before this wait can finish.
		a.serving.Wait()
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
	state atomic.Pointer[keyringState]
}

type keyringState struct {
	inner       agent.Agent
	certificate sshcert.RawCertificate
}

// newReadOnlyKeyring creates a readOnlyKeyring with an empty inner keyring,
// so List/Sign behave sanely before the first UseCredential call.
func newReadOnlyKeyring() *readOnlyKeyring {
	r := &readOnlyKeyring{}
	empty := agent.NewKeyring()
	r.state.Store(&keyringState{inner: empty})
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

	r.state.Store(&keyringState{inner: fresh, certificate: c.Certificate})
	return nil
}

// clear atomically replaces the live credential with an empty keyring.
func (r *readOnlyKeyring) clear() {
	empty := agent.NewKeyring()
	r.state.Store(&keyringState{inner: empty})
}

func (r *readOnlyKeyring) current() agent.Agent {
	return r.state.Load().inner
}

func (r *readOnlyKeyring) certificate() sshcert.RawCertificate {
	return r.state.Load().certificate
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
