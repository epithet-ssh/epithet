package policyserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/httpsig"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// Request from CA to policy server.
type Request struct {
	Token      string            `json:"token"`
	Connection policy.Connection `json:"connection"`
}

// Response from policy server to CA.
type Response struct {
	CertParams ca.CertParams `json:"certParams"`
	Policy     policy.Policy `json:"policy"`
}

// DiscoveryResponse is returned by GET / on the policy server.
// The CA fetches this and serves it to clients on /discovery.
type DiscoveryResponse struct {
	Auth          *BootstrapAuth `json:"auth"`
	MatchPatterns []string       `json:"matchPatterns,omitempty"`
}

// PolicyEvaluator makes authorization decisions based on identity and connection details.
// The token has already been validated and identity extracted by the handler.
// Implementations must:
// - Make authorization decision (allow/deny) based on identity
// - Return certificate parameters (principals, expiration, extensions) and policy (hostPattern)
// - Return appropriate errors for different failure modes
type PolicyEvaluator interface {
	// Evaluate makes an authorization decision for the given identity and connection.
	// The identity has already been extracted from a validated token.
	// The context is used for loading dynamic policy if configured.
	// Returns:
	// - *Response: Certificate parameters and policy if authorized
	// - error: If authorization denied
	//
	// Error handling:
	// - Return ErrForbidden (403) if access denied by policy
	// - Return other errors (500) for internal errors
	Evaluate(ctx context.Context, identity string, conn policy.Connection) (*Response, error)
}

// TokenValidator validates authentication tokens and extracts identity.
// Used by handlers to authenticate requests before policy evaluation.
type TokenValidator interface {
	// ValidateAndExtractIdentity validates the token and returns the identity.
	// Returns an error if the token is invalid or expired.
	ValidateAndExtractIdentity(token string) (identity string, err error)
}

// Standard errors for policy evaluation.
var (
	// ErrUnauthorized indicates token is invalid or expired (401).
	ErrUnauthorized = &PolicyError{StatusCode: http.StatusUnauthorized, Message: "Unauthorized"}

	// ErrForbidden indicates token valid but access denied by policy (403).
	ErrForbidden = &PolicyError{StatusCode: http.StatusForbidden, Message: "Forbidden"}

	// ErrNotHandled indicates this policy server does not handle the connection (422).
	ErrNotHandled = &PolicyError{StatusCode: http.StatusUnprocessableEntity, Message: "connection not handled"}
)

// PolicyError represents a policy evaluation error with HTTP status code.
type PolicyError struct {
	StatusCode int
	Message    string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("policy error %d: %s", e.StatusCode, e.Message)
}

// Unauthorized returns a 401 error with the given message.
func Unauthorized(message string) error {
	return &PolicyError{StatusCode: http.StatusUnauthorized, Message: message}
}

// Forbidden returns a 403 error with the given message.
func Forbidden(message string) error {
	return &PolicyError{StatusCode: http.StatusForbidden, Message: message}
}

// InternalError returns a 500 error with the given message.
func InternalError(message string) error {
	return &PolicyError{StatusCode: http.StatusInternalServerError, Message: message}
}

// NotHandled returns a 422 error indicating this policy server does not handle
// the requested connection. The CA will return 422 to the client.
func NotHandled(message string) error {
	return &PolicyError{StatusCode: http.StatusUnprocessableEntity, Message: message}
}

// Config configures the policy server HTTP handler.
type Config struct {
	// CAPublicKey is the CA's SSH public key for verifying RFC 9421 request signatures.
	// If empty, signature verification is skipped (not recommended for production).
	CAPublicKey sshcert.RawPublicKey

	// Validator validates tokens and extracts identity (authentication).
	Validator TokenValidator

	// Evaluator makes authorization decisions based on identity.
	Evaluator PolicyEvaluator

	// MaxRequestSize limits the request body size (default: 8192 bytes).
	MaxRequestSize int64

	// Discovery is the configuration returned on GET / requests.
	// The CA fetches this to serve discovery data to clients.
	Discovery *DiscoveryResponse
}

// handler holds the config and implements the HTTP handler methods.
type handler struct {
	config   Config
	verifier *httpsig.Verifier // nil if CAPublicKey is empty.
}

// NewHandler creates an HTTP handler for the policy server.
// The handler supports:
//
//	GET /  — returns discovery data (auth, match patterns, default expiration)
//	POST / — evaluates a cert request (token + connection)
//
// All requests are verified using RFC 9421 HTTP Message Signatures if
// CAPublicKey is configured.
func NewHandler(config Config) http.Handler {
	if config.MaxRequestSize == 0 {
		config.MaxRequestSize = 8192
	}
	h := &handler{config: config}

	// Create RFC 9421 verifier if CA public key is provided.
	if config.CAPublicKey != "" {
		v, err := httpsig.NewVerifier(config.CAPublicKey)
		if err != nil {
			// This is a startup-time configuration error.
			panic(fmt.Sprintf("failed to create HTTP signature verifier: %v", err))
		}
		h.verifier = v
	}

	return h
}

// ServeHTTP routes requests by method.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Verify RFC 9421 signature on all requests.
	if h.verifier != nil {
		if err := h.verifier.VerifyRequest(r); err != nil {
			h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("signature verification failed: %v", err))
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		h.handleDiscovery(w, r)
	case http.MethodPost:
		h.handleCertRequest(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleDiscovery returns discovery data as JSON.
// This endpoint is called by the CA to populate its /discovery endpoint.
func (h *handler) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	if h.config.Discovery == nil {
		h.writeError(w, http.StatusNotFound, "discovery not configured")
		return
	}

	w.Header().Set("Cache-Control", "max-age=300")
	h.writeJSON(w, http.StatusOK, h.config.Discovery)
}

// handleCertRequest processes a cert evaluation request.
func (h *handler) handleCertRequest(w http.ResponseWriter, r *http.Request) {
	// Parse request body.
	body, err := io.ReadAll(io.LimitReader(r.Body, h.config.MaxRequestSize))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to read request: %v", err))
		return
	}
	defer r.Body.Close()

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	// Decode the base64url-encoded token.
	// Tokens are always base64url encoded by the broker to preserve arbitrary bytes.
	decodedToken, err := base64.RawURLEncoding.DecodeString(req.Token)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid token encoding: %v", err))
		return
	}

	// Validate token and extract identity (authentication).
	identity, err := h.config.Validator.ValidateAndExtractIdentity(string(decodedToken))
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Invalid token: %v", err))
		return
	}

	// Evaluate policy based on identity (authorization).
	resp, err := h.config.Evaluator.Evaluate(r.Context(), identity, req.Connection)
	if err != nil {
		if policyErr, ok := err.(*PolicyError); ok {
			h.writeError(w, policyErr.StatusCode, policyErr.Message)
			return
		}
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// writeError writes an error response as plain text.
func (h *handler) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

// writeJSON writes a JSON response.
func (h *handler) writeJSON(w http.ResponseWriter, statusCode int, data any) {
	body, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal response: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(body)
}
