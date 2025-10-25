package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
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
	agents           map[policy.ConnectionHash]agentEntry // connectionHash → agent
	caClient         *caclient.Client
	agentSocketDir   string // Directory for agent sockets (e.g., ~/.epithet/sockets)
}

// New creates a new Broker instance. This does not start listening - call Serve() to begin accepting connections.
func New(log slog.Logger, socketPath string, authCommand string, caURL string, agentSocketDir string) *Broker {
	return &Broker{
		auth:             NewAuth(authCommand),
		certStore:        NewCertificateStore(),
		agents:           make(map[policy.ConnectionHash]agentEntry),
		brokerSocketPath: socketPath,
		caClient:         caclient.New(caURL),
		agentSocketDir:   agentSocketDir,
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

	// Step 2: Check for existing, valid certificate in cert store
	cred, found := b.certStore.Lookup(input.Connection)
	if found {
		b.log.Debug("found valid certificate in store", "host", input.Connection.RemoteHost)
		// Step 3: Set up agent with existing certificate
		err := b.ensureAgent(input.Connection.Hash, cred)
		if err != nil {
			b.log.Error("failed to create agent", "error", err)
			output.Allow = false
			output.Error = fmt.Sprintf("failed to create agent: %v", err)
			return nil
		}
		output.Allow = true
		return nil
	}

	// Step 4: No valid certificate exists, request one from CA
	b.log.Debug("no valid certificate found, requesting from CA", "host", input.Connection.RemoteHost)

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

	// Generate ephemeral keypair for this connection
	publicKey, privateKey, err := sshcert.GenerateKeys()
	if err != nil {
		b.log.Error("failed to generate keypair", "error", err)
		output.Allow = false
		output.Error = fmt.Sprintf("failed to generate keypair: %v", err)
		return nil
	}

	// Request certificate from CA
	certResp, err := b.caClient.GetCert(context.Background(), &caserver.CreateCertRequest{
		PublicKey:  publicKey,
		Token:      token,
		Connection: input.Connection,
	})
	if err != nil {
		b.log.Error("failed to request certificate from CA", "error", err)
		output.Allow = false
		output.Error = fmt.Sprintf("failed to request certificate: %v", err)
		return nil
	}

	// Store the certificate with policy and expiration
	// Note: We need to parse the certificate to get the actual expiration time
	// For now, we'll use a reasonable default based on typical epithet cert lifetime
	expiresAt := time.Now().Add(5 * time.Minute) // TODO: Parse cert to get actual expiry
	b.certStore.Store(PolicyCert{
		Policy:     certResp.Policy,
		Credential: agent.Credential{PrivateKey: privateKey, Certificate: certResp.Certificate},
		ExpiresAt:  expiresAt,
	})

	b.log.Debug("certificate obtained and stored", "host", input.Connection.RemoteHost, "policy", certResp.Policy.HostPattern)

	// Step 3: Create agent with new certificate
	credential := agent.Credential{
		PrivateKey:  privateKey,
		Certificate: certResp.Certificate,
	}
	err = b.ensureAgent(input.Connection.Hash, credential)
	if err != nil {
		b.log.Error("failed to create agent", "error", err)
		output.Allow = false
		output.Error = fmt.Sprintf("failed to create agent: %v", err)
		return nil
	}

	output.Allow = true
	return nil
}

// ensureAgent ensures an agent exists for the given connection hash with the given credential.
// If an agent already exists, it updates the credential. If not, it creates a new agent.
func (b *Broker) ensureAgent(connectionHash policy.ConnectionHash, credential agent.Credential) error {
	// Check if agent already exists
	if entry, exists := b.agents[connectionHash]; exists {
		// Update the existing agent's credential
		b.log.Debug("updating existing agent credential", "hash", connectionHash)
		err := entry.agent.UseCredential(credential)
		if err != nil {
			return fmt.Errorf("failed to update agent credential: %w", err)
		}
		// Update expiration time (TODO: parse from cert)
		entry.expiresAt = time.Now().Add(5 * time.Minute)
		b.agents[connectionHash] = entry
		return nil
	}

	// Create new agent
	socketPath := filepath.Join(b.agentSocketDir, string(connectionHash))
	b.log.Debug("creating new agent", "hash", connectionHash, "socket", socketPath)

	// Ensure the socket directory exists
	err := os.MkdirAll(b.agentSocketDir, 0700)
	if err != nil {
		return fmt.Errorf("failed to create agent socket directory: %w", err)
	}

	// Create the agent (Note: agent.New expects *caclient.Client, but we don't need it for UseCredential)
	// We pass nil because we're manually managing certificates via UseCredential
	ag, err := agent.New(nil, socketPath)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	// Start the agent in background
	go func() {
		err := ag.Serve(context.Background())
		if err != nil && err != context.Canceled {
			b.log.Error("agent serve error", "hash", connectionHash, "error", err)
		}
	}()

	// Set the credential
	err = ag.UseCredential(credential)
	if err != nil {
		ag.Close()
		return fmt.Errorf("failed to set agent credential: %w", err)
	}

	// Store the agent entry
	b.agents[connectionHash] = agentEntry{
		agent:     ag,
		expiresAt: time.Now().Add(5 * time.Minute), // TODO: parse from cert
	}

	b.log.Info("agent created and started", "hash", connectionHash, "socket", socketPath)
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
		b.agents = make(map[policy.ConnectionHash]agentEntry)
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
