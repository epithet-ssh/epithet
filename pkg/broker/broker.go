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
	pb "github.com/epithet-ssh/epithet/pkg/brokerv1"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"google.golang.org/grpc"
)

const (
	// maxRetries is the maximum number of retry attempts for CA 401 errors and auth plugin failures
	maxRetries = 3

	// cleanupInterval is how often the broker checks for expired agents to clean up
	cleanupInterval = 30 * time.Second
)

// agentEntry tracks a running agent and when its certificate expires
type agentEntry struct {
	agent       *agent.Agent
	expiresAt   time.Time
	certificate sshcert.RawCertificate
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
//   - Match() only holds b.lock around agents-map access, never across auth or
//     CA calls, so concurrent matches can share an in-flight auth attempt.
//     Concurrent matches for the same connection may each request a
//     certificate from the CA; ensureAgent() reconciles them (last one wins).
//   - ensureAgent() acquires b.lock itself; do not call it with b.lock held
//
// Immutable after New(): brokerSocketPath, agentSocketDir, caClient, log
// Protected by b.lock: agents map
// Protected by closeOnce: brokerListener, done channel
// Self-synchronized: auth (has internal lock), certStore (has internal lock)
type Broker struct {
	lock      sync.Mutex // Protects agents map
	done      chan struct{}
	ready     chan struct{} // Closed when broker is ready to accept connections
	closeOnce sync.Once
	log       slog.Logger // Immutable after New()

	brokerSocketPath string // Immutable after New()
	brokerListener   net.Listener

	auth      *Auth                                // Has internal locking, safe to call concurrently
	certStore *CertificateStore                    // Has internal locking, safe to call concurrently
	agents    map[policy.ConnectionHash]agentEntry // Protected by b.lock

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
func New(log slog.Logger, socketPath string, authCommand string, caClient *caclient.Client, agentSocketDir string, options ...Option) (*Broker, error) {
	if caClient == nil {
		return nil, fmt.Errorf("caClient is required")
	}

	b := &Broker{
		auth:             NewAuth(authCommand),
		certStore:        NewCertificateStore(),
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

type MatchRequest struct {
	Connection policy.Connection
}

type MatchResponse struct {
	// Should the `Match exec` actually match?
	Allow bool

	// Error contains any error which should be reported to the user on stderr
	Error string
}

// InspectRequest is the input for Broker.Inspect RPC
type InspectRequest struct{}

// AgentInfo contains information about a running agent
type AgentInfo struct {
	Hash        string                 `json:"hash"`
	SocketPath  string                 `json:"socketPath"`
	ExpiresAt   time.Time              `json:"expiresAt"`
	Certificate sshcert.RawCertificate `json:"certificate"`
}

// CertInfo contains information about a stored certificate
type CertInfo struct {
	Certificate sshcert.RawCertificate `json:"certificate"`
	Policy      policy.Policy          `json:"policy"`
	ExpiresAt   time.Time              `json:"expiresAt"`
}

// CAEndpointInfo contains the current state of a CA endpoint.
type CAEndpointInfo struct {
	URL      string `json:"url"`
	Priority int    `json:"priority"`
	State    string `json:"state"` // "closed", "open", "half-open"
}

// InspectResponse contains the current broker state
type InspectResponse struct {
	SocketPath        string           `json:"socketPath"`
	AgentSocketDir    string           `json:"agentSocketDir"`
	DiscoveryPatterns []string         `json:"discoveryPatterns,omitempty"` // Fetched live from CA (HTTP cached)
	Agents            []AgentInfo      `json:"agents"`
	Certificates      []CertInfo       `json:"certificates"`
	CAEndpoints       []CAEndpointInfo `json:"caEndpoints"`
}

// Match is invoked via rpc from `epithet match` invocations.
func (b *Broker) Match(input MatchRequest, output *MatchResponse) error {
	result := b.MatchWithUserOutput(context.Background(), input.Connection, nil)
	output.Allow = result.Allow
	output.Error = result.Error
	return nil
}

// MatchWithUserOutput performs the match operation, streaming auth user output
// to userOutput. This is the core match implementation used by the gRPC server.
// Canceling ctx (e.g. the requesting `epithet match` process went away)
// abandons this match's auth and CA work.
func (b *Broker) MatchWithUserOutput(ctx context.Context, conn policy.Connection, userOutput io.Writer) MatchResponse {
	b.log.Debug("match request received", "connection", conn)

	// Step 1: Check if this host should be handled by epithet at all.
	if !b.shouldHandle(ctx, conn.RemoteHost, userOutput) {
		b.log.Debug("host does not match discovery patterns", "host", conn.RemoteHost)
		// No error - this is normal, just means epithet doesn't handle this host.
		return MatchResponse{Allow: false}
	}

	// Step 2: Check if agent already exists for this connection hash.
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

	// Step 3: Check for existing, valid certificate in cert store.
	cred, found := b.certStore.Lookup(conn)
	if found {
		b.log.Debug("found valid certificate in store", "host", conn.RemoteHost)
		// Step 4: Set up agent with existing certificate.
		err := b.ensureAgent(conn.Hash, cred)
		if err != nil {
			b.log.Error("failed to create agent", "error", err)
			return MatchResponse{Allow: false, Error: fmt.Sprintf("failed to create agent: %v", err)}
		}
		return MatchResponse{Allow: true}
	}

	// Step 5: No valid certificate exists, request one from CA.
	b.log.Debug("no valid certificate found, requesting from CA", "host", conn.RemoteHost)

	// Generate ephemeral keypair for this connection.
	publicKey, privateKey, err := sshcert.GenerateKeys()
	if err != nil {
		b.log.Error("failed to generate keypair", "error", err)
		return MatchResponse{Allow: false, Error: fmt.Sprintf("failed to generate keypair: %v", err)}
	}

	// Request certificate with retry logic for 401 errors.
	var certResp *caclient.CertResponse
	for attempt := range maxRetries {
		if attempt > 0 {
			b.log.Debug("retrying certificate request", "attempt", attempt+1, "max", maxRetries)
		}

		// Ensure we have an auth token.
		token := b.auth.Token()
		if token == "" {
			b.log.Debug("no auth token, authenticating")
			token, err = b.auth.Run(ctx, nil, userOutput)
			if err != nil {
				// Auth command failed - don't retry automatically.
				// User should fix the issue and retry the SSH connection.
				b.log.Error("authentication failed", "error", err)
				return MatchResponse{Allow: false, Error: fmt.Sprintf("authentication failed: %v", err)}
			}
			b.log.Debug("authentication successful")
		}

		// Request certificate from CA.
		certResp, err = b.caClient.GetCert(ctx, token, &caserver.CreateCertRequest{
			PublicKey:  publicKey,
			Connection: conn,
		})

		if err == nil {
			// Success!
			break
		}

		// Check error type for appropriate handling.
		var invalidToken *caclient.InvalidTokenError
		if errors.As(err, &invalidToken) {
			// Token is invalid/expired - clear and retry.
			b.log.Warn("token invalid or expired, clearing and retrying", "attempt", attempt+1)
			b.auth.ClearToken()
			continue
		}

		var policyDenied *caclient.PolicyDeniedError
		if errors.As(err, &policyDenied) {
			// Policy denied - don't retry, keep token.
			b.log.Error("CA policy denied access", "error", policyDenied.Message)
			return MatchResponse{Allow: false, Error: policyDenied.Error()}
		}

		var caUnavailable *caclient.CAUnavailableError
		if errors.As(err, &caUnavailable) {
			// CA unavailable - don't retry, keep token.
			b.log.Error("CA service unavailable", "error", caUnavailable.Message)
			return MatchResponse{Allow: false, Error: caUnavailable.Error()}
		}

		var allCAsUnavailable *caclient.AllCAsUnavailableError
		if errors.As(err, &allCAsUnavailable) {
			// All CAs are in circuit breaker - don't retry.
			b.log.Error("all CA servers unavailable", "error", allCAsUnavailable.Message)
			return MatchResponse{Allow: false, Error: allCAsUnavailable.Error()}
		}

		var invalidRequest *caclient.InvalidRequestError
		if errors.As(err, &invalidRequest) {
			// Invalid request - don't retry, keep token.
			b.log.Error("invalid certificate request", "error", invalidRequest.Message)
			return MatchResponse{Allow: false, Error: invalidRequest.Error()}
		}

		var connNotHandled *caclient.ConnectionNotHandledError
		if errors.As(err, &connNotHandled) {
			// CA/policy does not handle this connection - fail match, let SSH fall through.
			b.log.Info("connection not handled by CA", "error", connNotHandled.Message)
			return MatchResponse{Allow: false, Error: connNotHandled.Error()}
		}

		// Other errors (network, etc.) - fail without retry.
		b.log.Error("failed to request certificate from CA", "error", err)
		return MatchResponse{Allow: false, Error: fmt.Sprintf("failed to request certificate: %v", err)}
	}

	// Check if we exhausted retries.
	if err != nil {
		b.log.Error("exhausted retries requesting certificate", "attempts", maxRetries)
		return MatchResponse{Allow: false, Error: "authentication failed after multiple attempts"}
	}

	// Store the certificate with policy and expiration.
	expiresAt, err := certResp.Certificate.Expiry()
	if err != nil {
		b.log.Error("failed to parse certificate expiry", "error", err)
		return MatchResponse{Allow: false, Error: fmt.Sprintf("failed to parse certificate expiry: %v", err)}
	}
	b.certStore.Store(PolicyCert{
		Policy:     certResp.Policy,
		Credential: agent.Credential{PrivateKey: privateKey, Certificate: certResp.Certificate},
		ExpiresAt:  expiresAt,
	})

	b.log.Debug("certificate obtained and stored", "host", conn.RemoteHost, "user", conn.RemoteUser, "policy", certResp.Policy.HostUsers)

	// Step 6: Create agent with new certificate.
	credential := agent.Credential{
		PrivateKey:  privateKey,
		Certificate: certResp.Certificate,
	}
	err = b.ensureAgent(conn.Hash, credential)
	if err != nil {
		b.log.Error("failed to create agent", "error", err)
		return MatchResponse{Allow: false, Error: fmt.Sprintf("failed to create agent: %v", err)}
	}

	return MatchResponse{Allow: true}
}

// ensureAgent ensures an agent exists for the given connection hash with the given credential.
// If an agent already exists, it updates the credential. If not, it creates a new agent.
//
// Acquires b.lock for the duration; do not call with b.lock held.
func (b *Broker) ensureAgent(connectionHash policy.ConnectionHash, credential agent.Credential) error {
	b.lock.Lock()
	defer b.lock.Unlock()

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
		agent:       ag,
		expiresAt:   expiresAt,
		certificate: credential.Certificate,
	}

	b.log.Info("agent created and started", "hash", connectionHash, "socket", socketPath)
	return nil
}

// shouldHandle reports whether epithet should handle this connection.
//
// TEMPORARY until Task 14: server-advertised match patterns are gone from
// the wire format (Task 8), but the gating call site here hasn't been
// removed yet. Until then, treat a successfully fetched discovery document
// as "handle everything" — the hostname is no longer consulted.
func (b *Broker) shouldHandle(ctx context.Context, hostname string, userOutput io.Writer) bool {
	discovery, err := b.getDiscoveryPatterns(ctx, userOutput)
	if err != nil {
		b.log.Error("failed to get discovery", "error", err)
		return false // Can't determine - don't handle
	}

	return discovery != nil
}

// getDiscoveryPatterns fetches discovery patterns, authenticating and calling Hello if needed.
func (b *Broker) getDiscoveryPatterns(ctx context.Context, userOutput io.Writer) (*wire.Discovery, error) {
	// Fast path: try cached discovery first.
	token := b.auth.Token()
	if token != "" {
		discovery, err := b.caClient.GetDiscovery(ctx, token)
		if err == nil && discovery != nil {
			return discovery, nil
		}
		// Discovery fetch failed or no cached URL - continue to Hello.
	}

	// Slow path: authenticate if needed, then Hello to learn discovery URL.
	if token == "" {
		b.log.Debug("no auth token, authenticating to get discovery")
		var err error
		token, err = b.auth.Run(ctx, nil, userOutput)
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Call Hello to learn discovery URL from Link header.
	b.log.Debug("calling Hello to learn discovery URL")
	err := b.caClient.Hello(ctx, token)
	if err != nil {
		// If token expired, clear it, re-authenticate, and retry Hello.
		var invalidToken *caclient.InvalidTokenError
		if errors.As(err, &invalidToken) {
			b.log.Debug("token expired during Hello, re-authenticating")
			b.auth.ClearToken()
			token, err = b.auth.Run(ctx, nil, userOutput)
			if err != nil {
				return nil, fmt.Errorf("authentication failed: %w", err)
			}
			err = b.caClient.Hello(ctx, token)
			if err != nil {
				return nil, fmt.Errorf("hello failed after re-auth: %w", err)
			}
		} else {
			return nil, fmt.Errorf("hello failed: %w", err)
		}
	}

	// Now GetDiscovery should work (URL was cached by Hello).
	return b.caClient.GetDiscovery(ctx, token)
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
	server := grpc.NewServer()
	pb.RegisterBrokerServiceServer(server, NewBrokerServer(b))

	// Monitor context cancellation to trigger graceful shutdown.
	go func() {
		<-ctx.Done()
		server.GracefulStop()
	}()

	// Serve blocks until GracefulStop is called.
	if err := server.Serve(b.brokerListener); err != nil {
		// Check if error is from shutdown.
		select {
		case <-ctx.Done():
			// Expected during shutdown.
			return
		default:
			b.log.Error("gRPC server error", "error", err)
		}
	}
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

// Inspect is invoked via RPC from `epithet inspect` to get broker state
func (b *Broker) Inspect(_ InspectRequest, output *InspectResponse) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	output.SocketPath = b.brokerSocketPath
	output.AgentSocketDir = b.agentSocketDir

	// output.DiscoveryPatterns is left empty: server-advertised match
	// patterns were removed from the wire format in Task 8. The field
	// itself is still defined on the (generated) proto message; it goes
	// away when the RPC gating is rewired in Task 14.

	// Get agent info
	output.Agents = make([]AgentInfo, 0, len(b.agents))
	for hash, entry := range b.agents {
		socketPath := filepath.Join(b.agentSocketDir, string(hash))
		output.Agents = append(output.Agents, AgentInfo{
			Hash:        string(hash),
			SocketPath:  socketPath,
			ExpiresAt:   entry.expiresAt,
			Certificate: entry.certificate,
		})
	}

	// Get certificate info
	output.Certificates = b.certStore.List()

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
