package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// cleanupInterval is how often the broker checks for expired agents to clean up
const cleanupInterval = 30 * time.Second

// expiryBuffer is the time buffer before certificate expiration.
// Certificates are considered expired this much time before their actual expiration
// to account for:
// - Socket setup and IPC delays (~100ms)
// - SSH protocol negotiation and network transmission (~500ms-2s)
// - Clock skew between client and server (±2s)
// - General processing overhead (~100ms)
// With short-lived certificates (2+ minutes), this 5s buffer provides safety
// without meaningfully reducing usability.
const expiryBuffer = 5 * time.Second

// agentEntry tracks a running agent and when its certificate expires
type agentEntry struct {
	agent       *agent.Agent
	connection  policy.Connection
	expiresAt   time.Time
	certificate sshcert.RawCertificate
}

// Broker manages authentication and per-connection SSH agents. Certificates
// are minted fresh from the CA for every match past the agents-map fast path
// - there is no cross-connection certificate cache.
//
// Concurrency: Broker is safe for concurrent access from multiple RPC clients.
// The primary lock (b.lock) protects the agents map and coordinates with Auth.
//
// Locking invariants:
//   - b.lock protects: agents map (both reads and writes)
//   - Auth has its own internal lock (auth.mu) - safe to call without b.lock
//   - Match() only holds b.lock around agents-map access, never across auth or
//     CA calls, so concurrent matches can share an in-flight auth attempt.
//     Concurrent matches for the same connection may each request a
//     certificate from the CA; ensureAgent() reconciles them (last one wins).
//   - ensureAgent() acquires b.lock itself; do not call it with b.lock held
//
// Immutable after New(): brokerSocketPath, agentSocketDir, caClient, log
// Protected by b.lock: agents map
// Protected by closeOnce: brokerListener, done channel
// Self-synchronized: auth (has internal lock)
type Broker struct {
	lock      sync.Mutex // Protects agents map
	done      chan struct{}
	ready     chan struct{} // Closed when broker is ready to accept connections
	closeOnce sync.Once
	log       slog.Logger // Immutable after New()

	brokerSocketPath string // Immutable after New()
	brokerListener   net.Listener

	auth   *Auth                                // Has internal locking, safe to call concurrently
	agents map[policy.ConnectionHash]agentEntry // Protected by b.lock

	caClient       *caclient.Client // Immutable after New()
	agentSocketDir string           // Immutable after New()

	// For graceful shutdown: track in-flight RPC connections
	activeRPC       sync.WaitGroup
	shutdownTimeout time.Duration // Timeout for waiting on in-flight RPCs during shutdown
}

// Option configures the Broker
type Option interface {
	apply(*Broker) error
}

type optionFunc func(*Broker) error

func (f optionFunc) apply(b *Broker) error {
	return f(b)
}

// New creates a new Broker instance. This does not start listening - call Serve() to begin accepting connections.
func New(log slog.Logger, socketPath string, fetch TokenFunc, caClient *caclient.Client, agentSocketDir string, options ...Option) (*Broker, error) {
	if caClient == nil {
		return nil, fmt.Errorf("caClient is required")
	}

	b := &Broker{
		auth:             NewAuth(fetch),
		agents:           make(map[policy.ConnectionHash]agentEntry),
		brokerSocketPath: socketPath,
		agentSocketDir:   agentSocketDir,
		caClient:         caClient,
		done:             make(chan struct{}),
		ready:            make(chan struct{}),
		log:              log,
		shutdownTimeout:  2 * time.Second, // Default timeout for graceful shutdown
	}

	for _, o := range options {
		if err := o.apply(b); err != nil {
			return nil, err
		}
	}

	return b, nil
}

// SetShutdownTimeout sets the timeout for waiting on in-flight RPCs during shutdown.
// Use 0 to skip waiting (useful for tests).
func (b *Broker) SetShutdownTimeout(d time.Duration) {
	b.shutdownTimeout = d
}

// Ready returns a channel that is closed when the broker is ready to accept connections.
// Use this to wait for the broker to start: <-b.Ready()
func (b *Broker) Ready() <-chan struct{} {
	return b.ready
}

// Serve starts the broker listening on the configured socket and blocks until the context is cancelled.
// Returns an error if the listener cannot be started, otherwise returns ctx.Err() when shutdown completes.
func (b *Broker) Serve(ctx context.Context) error {
	if err := b.startBrokerListener(); err != nil {
		return fmt.Errorf("unable to start broker socket: %w", err)
	}

	// Signal that we're ready to accept connections
	close(b.ready)

	// Serve connections in background
	go b.serve(ctx)

	// Start background cleanup of expired agents
	go b.cleanupExpiredAgents(ctx)

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

type MatchResponse struct {
	// Should the `Match exec` actually match?
	Allow bool `json:"allow"`

	// Error contains any error which should be reported to the user on stderr
	Error string `json:"error,omitempty"`
}

// InspectRequest is the input for Broker.Inspect over the JSON line protocol
type InspectRequest struct{}

// AgentInfo contains information about a running agent
type AgentInfo struct {
	Hash        string                 `json:"hash"`
	Connection  policy.Connection      `json:"connection"`
	SocketPath  string                 `json:"socketPath"`
	ExpiresAt   time.Time              `json:"expiresAt"`
	Certificate sshcert.RawCertificate `json:"certificate"`
}

// CAEndpointInfo contains the current state of a CA endpoint.
type CAEndpointInfo struct {
	URL      string `json:"url"`
	Priority int    `json:"priority"`
	State    string `json:"state"` // "closed", "open", "half-open"
}

// InspectResponse contains the current broker state
type InspectResponse struct {
	SocketPath     string           `json:"socketPath"`
	AgentSocketDir string           `json:"agentSocketDir"`
	Agents         []AgentInfo      `json:"agents"`
	CAEndpoints    []CAEndpointInfo `json:"caEndpoints"`
}

// deny logs a match failure and builds the corresponding denial response.
func (b *Broker) deny(err error) MatchResponse {
	b.log.Error("match failed", "error", err)
	return MatchResponse{Allow: false, Error: err.Error()}
}

// MatchWithUserOutput performs the match operation, streaming auth user output
// to userOutput. This is the core match implementation used by the JSON
// protocol server (protocol.go). Canceling ctx (e.g. the requesting
// `epithet match` process went away) abandons this match's auth and CA work.
func (b *Broker) MatchWithUserOutput(ctx context.Context, conn policy.Connection, userOutput io.Writer) MatchResponse {
	b.log.Debug("match request received", "connection", conn)

	// Step 1: Check if agent already exists for this connection hash.
	b.lock.Lock()
	if entry, exists := b.agents[conn.Hash]; exists {
		// Check if agent's certificate is still valid (with buffer).
		if time.Now().Add(expiryBuffer).Before(entry.expiresAt) {
			b.log.Debug("found existing valid agent", "hash", conn.Hash, "expires", entry.expiresAt)
			b.lock.Unlock()
			return MatchResponse{Allow: true}
		}
		// Agent expired - clean it up.
		b.log.Debug("cleaning up expired agent", "hash", conn.Hash, "expired", entry.expiresAt)
		entry.agent.Close()
		delete(b.agents, conn.Hash)
	}
	b.lock.Unlock()

	// Step 2: No agent exists (or it just expired). Mint a fresh,
	// per-connection certificate - certs are never cached or reused across
	// connections, so every match past the fast path talks to the CA.
	b.log.Debug("no existing agent, requesting certificate from CA", "host", conn.RemoteHost)

	// Generate ephemeral keypair for this connection.
	publicKey, privateKey, err := sshcert.GenerateKeys()
	if err != nil {
		return b.deny(fmt.Errorf("failed to generate keypair: %w", err))
	}

	token, err := b.auth.Token(ctx, userOutput)
	if err != nil {
		return b.deny(fmt.Errorf("authentication failed: %w", err))
	}

	certResp, err := b.caClient.GetCert(ctx, token, &caserver.CreateCertRequest{
		PublicKey: publicKey, Connection: conn,
	})
	var invalidToken *caclient.InvalidTokenError
	if errors.As(err, &invalidToken) {
		// Safety net: server-side revocation or clock skew. One forced refresh.
		b.log.Warn("CA rejected token despite local validity, refreshing once")
		token, err = b.auth.ForceRefresh(ctx, userOutput)
		if err != nil {
			return b.deny(fmt.Errorf("re-authentication failed: %w", err))
		}
		certResp, err = b.caClient.GetCert(ctx, token, &caserver.CreateCertRequest{
			PublicKey: publicKey, Connection: conn,
		})
	}
	if err != nil {
		return b.deny(fmt.Errorf("certificate request failed: %w", err))
	}

	b.log.Debug("certificate obtained", "host", conn.RemoteHost, "user", conn.RemoteUser)

	// Step 3: Create agent with new certificate.
	credential := agent.Credential{
		PrivateKey:  privateKey,
		Certificate: certResp.Certificate,
	}
	if err := b.ensureAgent(conn, credential); err != nil {
		return b.deny(fmt.Errorf("failed to create agent: %w", err))
	}

	return MatchResponse{Allow: true}
}

// ensureAgent ensures an agent exists for the given connection with the given credential.
// If an agent already exists, it updates the credential. If not, it creates a new agent.
//
// Acquires b.lock for the duration; do not call with b.lock held.
func (b *Broker) ensureAgent(connection policy.Connection, credential agent.Credential) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	connectionHash := connection.Hash

	// Check if agent already exists
	if entry, exists := b.agents[connectionHash]; exists {
		// Update the existing agent's credential
		b.log.Debug("updating existing agent credential", "hash", connectionHash)
		err := entry.agent.UseCredential(credential)
		if err != nil {
			return fmt.Errorf("failed to update agent credential: %w", err)
		}
		// Update expiration time and certificate
		expiresAt, err := credential.Certificate.Expiry()
		if err != nil {
			return fmt.Errorf("failed to parse certificate expiry: %w", err)
		}
		entry.expiresAt = expiresAt
		entry.certificate = credential.Certificate
		entry.connection = connection
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

	ag := agent.New(&b.log, socketPath)

	// Start the agent in background
	go func() {
		err := ag.Serve(context.Background())
		if err != nil && err != context.Canceled {
			b.log.Error("agent serve error", "hash", connectionHash, "error", err)
		}
	}()

	// Wait for the listener to actually start (or fail) before doing
	// anything else with this agent. This also gives the eventual Close()
	// call - which typically happens on a different goroutine (broker
	// shutdown or cleanup, not this one) - a happens-before relationship
	// with Serve's listener setup; without it that's a real data race, not
	// just a timing risk (see the Agent struct's comment in pkg/agent).
	if err := ag.WaitReady(); err != nil {
		return fmt.Errorf("failed to start agent listener: %w", err)
	}

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
		agent:       ag,
		connection:  connection,
		expiresAt:   expiresAt,
		certificate: credential.Certificate,
	}

	b.log.Info("agent created and started", "hash", connectionHash, "socket", socketPath)
	return nil
}

// AgentSocketPath returns the socket path for a given connection hash.
// This is used by SSH to connect to the per-connection agent.
func (b *Broker) AgentSocketPath(hash policy.ConnectionHash) string {
	return filepath.Join(b.agentSocketDir, string(hash))
}

func (b *Broker) serve(ctx context.Context) {
	b.serveProtocol(ctx, b.brokerListener)
}

func (b *Broker) Done() <-chan struct{} {
	return b.done
}

// cleanupExpiredAgents runs periodically to clean up agents with expired certificates.
// This proactively removes expired agent sockets and closes agent connections.
func (b *Broker) cleanupExpiredAgents(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.cleanupExpiredAgentsOnce()
		}
	}
}

// cleanupExpiredAgentsOnce performs a single cleanup pass over all agents.
// Separated from cleanupExpiredAgents to allow for testing.
func (b *Broker) cleanupExpiredAgentsOnce() {
	b.lock.Lock()
	defer b.lock.Unlock()

	now := time.Now().Add(expiryBuffer)
	expired := []policy.ConnectionHash{}

	// Find all expired agents
	for hash, entry := range b.agents {
		if now.After(entry.expiresAt) {
			expired = append(expired, hash)
		}
	}

	// Clean them up
	for _, hash := range expired {
		entry := b.agents[hash]
		b.log.Info("cleaning up expired agent", "hash", hash, "expired_at", entry.expiresAt)
		if entry.agent != nil {
			entry.agent.Close()
		}
		delete(b.agents, hash)
	}

	if len(expired) > 0 {
		b.log.Debug("cleanup complete", "removed_agents", len(expired))
	}
}

func (b *Broker) Close() {
	b.closeOnce.Do(func() {
		// Stop accepting new connections
		if b.brokerListener != nil {
			_ = b.brokerListener.Close()
		}

		// Wait for in-flight RPCs to complete (with timeout)
		if b.shutdownTimeout > 0 {
			done := make(chan struct{})
			go func() {
				b.activeRPC.Wait()
				close(done)
			}()

			select {
			case <-done:
				b.log.Debug("all in-flight RPCs completed")
			case <-time.After(b.shutdownTimeout):
				b.log.Warn("timeout waiting for in-flight RPCs, proceeding with shutdown")
			}
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

// Inspect is invoked by `epithet inspect` (over the broker's JSON line protocol) to get broker state.
func (b *Broker) Inspect(_ InspectRequest, output *InspectResponse) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	output.SocketPath = b.brokerSocketPath
	output.AgentSocketDir = b.agentSocketDir

	// Get agent info
	output.Agents = make([]AgentInfo, 0, len(b.agents))
	for hash, entry := range b.agents {
		socketPath := filepath.Join(b.agentSocketDir, string(hash))
		output.Agents = append(output.Agents, AgentInfo{
			Hash:        string(hash),
			Connection:  entry.connection,
			SocketPath:  socketPath,
			ExpiresAt:   entry.expiresAt,
			Certificate: entry.certificate,
		})
	}

	// Get CA endpoint status
	for _, ep := range b.caClient.EndpointStatus() {
		output.CAEndpoints = append(output.CAEndpoints, CAEndpointInfo{
			URL:      ep.URL,
			Priority: ep.Priority,
			State:    ep.BreakerState,
		})
	}

	return nil
}
