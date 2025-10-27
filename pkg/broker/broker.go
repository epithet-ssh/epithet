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

const (
	// maxRetries is the maximum number of retry attempts for CA 401 errors and auth plugin failures
	maxRetries = 3
)

// agentEntry tracks a running agent and when its certificate expires
type agentEntry struct {
	agent     *agent.Agent
	expiresAt time.Time
}

// Broker manages authentication, certificate storage, and per-connection SSH agents.
//
// Concurrency: Broker is safe for concurrent access from multiple RPC clients.
// The primary lock (b.lock) protects the agents map and coordinates with Auth and CertificateStore.
//
// Locking invariants:
//   - b.lock protects: agents map (both reads and writes)
//   - Auth has its own internal lock (auth.lock) - safe to call without b.lock
//   - CertificateStore has its own internal lock (certStore.lock) - safe to call without b.lock
//   - Match() holds b.lock for the entire operation to ensure atomic cert lookup + agent creation
//   - ensureAgent() MUST be called with b.lock held (caller responsibility)
//
// Immutable after New(): brokerSocketPath, agentSocketDir, matchPatterns, caClient, log
// Protected by b.lock: agents map
// Protected by closeOnce: brokerListener, done channel
// Self-synchronized: auth (has internal lock), certStore (has internal lock)
type Broker struct {
	lock      sync.Mutex // Protects agents map
	done      chan struct{}
	closeOnce sync.Once
	log       slog.Logger // Immutable after New()

	brokerSocketPath string // Immutable after New()
	brokerListener   net.Listener

	auth      *Auth                                // Has internal locking, safe to call concurrently
	certStore *CertificateStore                    // Has internal locking, safe to call concurrently
	agents    map[policy.ConnectionHash]agentEntry // Protected by b.lock

	caClient       *caclient.Client // Immutable after New()
	agentSocketDir string           // Immutable after New()
	matchPatterns  []string         // Immutable after New()
}

// New creates a new Broker instance. This does not start listening - call Serve() to begin accepting connections.
func New(log slog.Logger, socketPath string, authCommand string, caURL string, agentSocketDir string, matchPatterns []string) *Broker {
	return &Broker{
		auth:             NewAuth(authCommand),
		certStore:        NewCertificateStore(),
		agents:           make(map[policy.ConnectionHash]agentEntry),
		brokerSocketPath: socketPath,
		caClient:         caclient.New(caURL),
		agentSocketDir:   agentSocketDir,
		matchPatterns:    matchPatterns,
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

	// Step 1: Check if this host should be handled by epithet at all
	if !b.shouldHandle(input.Connection.RemoteHost) {
		b.log.Debug("host does not match any patterns, ignoring", "host", input.Connection.RemoteHost, "patterns", b.matchPatterns)
		output.Allow = false
		output.Error = fmt.Sprintf("host %s does not match any configured patterns", input.Connection.RemoteHost)
		return nil
	}

	// Step 2: Check if agent already exists for this connection hash
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

	// Step 3: Check for existing, valid certificate in cert store
	cred, found := b.certStore.Lookup(input.Connection)
	if found {
		b.log.Debug("found valid certificate in store", "host", input.Connection.RemoteHost)
		// Step 4: Set up agent with existing certificate
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

	// Step 5: No valid certificate exists, request one from CA
	b.log.Debug("no valid certificate found, requesting from CA", "host", input.Connection.RemoteHost)

	// Generate ephemeral keypair for this connection
	publicKey, privateKey, err := sshcert.GenerateKeys()
	if err != nil {
		b.log.Error("failed to generate keypair", "error", err)
		output.Allow = false
		output.Error = fmt.Sprintf("failed to generate keypair: %v", err)
		return nil
	}

	// Request certificate with retry logic for 401 errors
	var certResp *caserver.CreateCertResponse
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			b.log.Debug("retrying certificate request", "attempt", attempt+1, "max", maxRetries)
		}

		// Ensure we have an auth token
		token := b.auth.Token()
		if token == "" {
			b.log.Debug("no auth token, authenticating")
			token, err = b.auth.Run(nil) // TODO(epithet-42): pass connection details for template rendering
			if err != nil {
				// Check if this is a user-facing auth failure (don't retry)
				var authFailure *AuthFailureError
				if errors.As(err, &authFailure) {
					b.log.Error("authentication failed", "error", authFailure.Message)
					output.Allow = false
					output.Error = fmt.Sprintf("authentication failed: %v", authFailure.Message)
					return nil
				}
				// Unexpected error (non-zero exit) - will retry in outer loop
				b.log.Warn("auth command error, will retry", "error", err, "attempt", attempt+1)
				continue
			}
			b.log.Debug("authentication successful")
		}

		// Request certificate from CA
		certResp, err = b.caClient.GetCert(context.Background(), &caserver.CreateCertRequest{
			PublicKey:  publicKey,
			Token:      token,
			Connection: input.Connection,
		})

		if err == nil {
			// Success!
			break
		}

		// Check error type for appropriate handling
		var invalidToken *caclient.InvalidTokenError
		if errors.As(err, &invalidToken) {
			// Token is invalid/expired - clear and retry
			b.log.Warn("token invalid or expired, clearing and retrying", "attempt", attempt+1)
			b.auth.ClearToken()
			continue
		}

		var policyDenied *caclient.PolicyDeniedError
		if errors.As(err, &policyDenied) {
			// Policy denied - don't retry, keep token
			b.log.Error("CA policy denied access", "error", policyDenied.Message)
			output.Allow = false
			output.Error = policyDenied.Error()
			return nil
		}

		var caUnavailable *caclient.CAUnavailableError
		if errors.As(err, &caUnavailable) {
			// CA unavailable - don't retry, keep token
			b.log.Error("CA service unavailable", "error", caUnavailable.Message)
			output.Allow = false
			output.Error = caUnavailable.Error()
			return nil
		}

		var invalidRequest *caclient.InvalidRequestError
		if errors.As(err, &invalidRequest) {
			// Invalid request - don't retry, keep token
			b.log.Error("invalid certificate request", "error", invalidRequest.Message)
			output.Allow = false
			output.Error = invalidRequest.Error()
			return nil
		}

		// Other errors (network, etc.) - fail without retry
		b.log.Error("failed to request certificate from CA", "error", err)
		output.Allow = false
		output.Error = fmt.Sprintf("failed to request certificate: %v", err)
		return nil
	}

	// Check if we exhausted retries
	if err != nil {
		b.log.Error("exhausted retries requesting certificate", "attempts", maxRetries)
		output.Allow = false
		output.Error = "authentication failed after multiple attempts"
		return nil
	}

	// Store the certificate with policy and expiration
	expiresAt, err := certResp.Certificate.Expiry()
	if err != nil {
		b.log.Error("failed to parse certificate expiry", "error", err)
		output.Allow = false
		output.Error = fmt.Sprintf("failed to parse certificate expiry: %v", err)
		return nil
	}
	b.certStore.Store(PolicyCert{
		Policy:     certResp.Policy,
		Credential: agent.Credential{PrivateKey: privateKey, Certificate: certResp.Certificate},
		ExpiresAt:  expiresAt,
	})

	b.log.Debug("certificate obtained and stored", "host", input.Connection.RemoteHost, "policy", certResp.Policy.HostPattern)

	// Step 4: Create agent with new certificate
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
//
// REQUIRES: b.lock must be held by caller. This method modifies b.agents map.
func (b *Broker) ensureAgent(connectionHash policy.ConnectionHash, credential agent.Credential) error {
	// Check if agent already exists
	if entry, exists := b.agents[connectionHash]; exists {
		// Update the existing agent's credential
		b.log.Debug("updating existing agent credential", "hash", connectionHash)
		err := entry.agent.UseCredential(credential)
		if err != nil {
			return fmt.Errorf("failed to update agent credential: %w", err)
		}
		// Update expiration time from certificate
		expiresAt, err := credential.Certificate.Expiry()
		if err != nil {
			return fmt.Errorf("failed to parse certificate expiry: %w", err)
		}
		entry.expiresAt = expiresAt
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
	ag, err := agent.New(&b.log, nil, socketPath)
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

	// Parse certificate expiry
	expiresAt, err := credential.Certificate.Expiry()
	if err != nil {
		ag.Close()
		return fmt.Errorf("failed to parse certificate expiry: %w", err)
	}

	// Store the agent entry
	b.agents[connectionHash] = agentEntry{
		agent:     ag,
		expiresAt: expiresAt,
	}

	b.log.Info("agent created and started", "hash", connectionHash, "socket", socketPath)
	return nil
}

// shouldHandle checks if the given hostname matches any of the configured match patterns.
// Returns true if epithet should handle this connection, false otherwise.
func (b *Broker) shouldHandle(hostname string) bool {
	for _, pattern := range b.matchPatterns {
		matched, err := filepath.Match(pattern, hostname)
		if err != nil {
			b.log.Warn("invalid match pattern", "pattern", pattern, "error", err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// LookupCertificate finds a valid certificate for the given connection.
// Returns the Credential and true if found and not expired, otherwise returns false.
func (b *Broker) LookupCertificate(conn policy.Connection) (agent.Credential, bool) {
	return b.certStore.Lookup(conn)
}

// AgentSocketPath returns the socket path for a given connection hash.
// This is used by SSH to connect to the per-connection agent.
func (b *Broker) AgentSocketPath(hash policy.ConnectionHash) string {
	return filepath.Join(b.agentSocketDir, string(hash))
}

// BrokerSocketPath returns the path to the broker's RPC socket.
func (b *Broker) BrokerSocketPath() string {
	return b.brokerSocketPath
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
		// Only close listener if it was successfully created
		if b.brokerListener != nil {
			_ = b.brokerListener.Close()
		}

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
