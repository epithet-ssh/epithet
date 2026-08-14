package policyserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// PolicyEvaluator makes authorization decisions based on identity and connection details.
// The token has already been validated and identity extracted by the handler.
// Implementations must:
// - Make authorization decision (allow/deny) based on identity
// - Return certificate parameters (principals, expiration, extensions) and policy (hostPattern)
// - Return appropriate errors for different failure modes
type PolicyEvaluator interface {
	// Evaluate makes an authorization decision for the given identity and connection.
	// The identity has already been extracted from a validated token.
	// tokenExpiry is the auth token's expiry, used to clamp the issued
	// certificate's validity so it can never outlive the auth session that
	// requested it.
	// The context is used for loading dynamic policy if configured.
	// Returns:
	// - *wire.PolicyResponse: Certificate parameters and policy if authorized
	// - error: If authorization denied
	//
	// Error handling:
	// - Return ErrForbidden (403) if access denied by policy
	// - Return other errors (500) for internal errors
	Evaluate(ctx context.Context, identity string, tokenExpiry time.Time, conn policy.Connection) (*wire.PolicyResponse, error)
}

// Standard errors for policy evaluation.
var (
	// ErrUnauthorized indicates token is invalid or expired (401).
	ErrUnauthorized = &wire.PolicyError{StatusCode: http.StatusUnauthorized, Message: "Unauthorized"}

	// ErrForbidden indicates token valid but access denied by policy (403).
	ErrForbidden = &wire.PolicyError{StatusCode: http.StatusForbidden, Message: "Forbidden"}

	// ErrNotHandled indicates this policy server does not handle the connection (422).
	ErrNotHandled = &wire.PolicyError{StatusCode: http.StatusUnprocessableEntity, Message: "connection not handled"}
)

// Unauthorized returns a 401 error with the given message.
func Unauthorized(message string) error {
	return &wire.PolicyError{StatusCode: http.StatusUnauthorized, Message: message}
}

// Forbidden returns a 403 error with the given message.
func Forbidden(message string) error {
	return &wire.PolicyError{StatusCode: http.StatusForbidden, Message: message}
}

// InternalError returns a 500 error with the given message.
func InternalError(message string) error {
	return &wire.PolicyError{StatusCode: http.StatusInternalServerError, Message: message}
}

// NotHandled returns a 422 error indicating this policy server does not handle
// the requested connection. The CA will return 422 to the client.
func NotHandled(message string) error {
	return &wire.PolicyError{StatusCode: http.StatusUnprocessableEntity, Message: message}
}

// Config configures the policy server HTTP handler.
type Config struct {
	// CAPublicKey is the CA's SSH public key, used to verify the request-bound
	// JWT (pkg/serviceauth) on every request. Required.
	CAPublicKey sshcert.RawPublicKey

	// Validator validates tokens and extracts identity (authentication).
	Validator *oidc.Validator

	// Evaluator makes authorization decisions based on identity.
	Evaluator PolicyEvaluator

	// MaxRequestSize limits the request body size (default: 8192 bytes).
	MaxRequestSize int64

	// Discovery is the configuration returned on GET / requests.
	// The CA fetches this to serve discovery data to clients.
	Discovery *wire.Discovery
}

// handler holds the config and implements the HTTP handler methods.
type handler struct {
	config   Config
	verifier *serviceauth.Verifier
}

// NewHandler creates an HTTP handler for the policy server.
// The handler supports:
//
//	GET /  — returns discovery data (auth, match patterns, default expiration)
//	POST / — evaluates a cert request (token + connection)
//
// Every request must carry a valid CA-minted request token (pkg/serviceauth);
// CAPublicKey is therefore required.
func NewHandler(config Config) (http.Handler, error) {
	if config.CAPublicKey == "" {
		return nil, fmt.Errorf("CAPublicKey is required")
	}
	if config.MaxRequestSize == 0 {
		config.MaxRequestSize = 8192
	}

	verifier, err := serviceauth.NewVerifier(config.CAPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid CA public key: %w", err)
	}

	return &handler{config: config, verifier: verifier}, nil
}

// ServeHTTP reads the body once (needed for both verification and dispatch,
// which avoids the double body read RFC 9421's Content-Digest used to
// require), verifies the request token, then routes by method.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, h.config.MaxRequestSize))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to read request: %v", err))
		return
	}
	defer r.Body.Close()

	// GET requests read back an empty (non-nil) slice, which hashes
	// identically to the nil body the CA signed over for that request.
	// Verify takes r itself (not just the header) to check the htm/htu
	// claims against the method and target actually received.
	if err := h.verifier.Verify(r, body); err != nil {
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("request verification failed: %v", err))
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleDiscovery(w, r)
	case http.MethodPost:
		h.handleCertRequest(w, r, body)
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

// handleCertRequest processes a cert evaluation request. body was already
// read (and verified) by ServeHTTP.
func (h *handler) handleCertRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	var req wire.PolicyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	// Validate token and extract identity (authentication).
	claims, err := h.config.Validator.Validate(r.Context(), req.Token)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Invalid token: %v", err))
		return
	}

	// Evaluate policy based on identity (authorization).
	resp, err := h.config.Evaluator.Evaluate(r.Context(), claims.Identity, claims.ExpiresAt, req.Connection)
	if err != nil {
		if policyErr, ok := err.(*wire.PolicyError); ok {
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
