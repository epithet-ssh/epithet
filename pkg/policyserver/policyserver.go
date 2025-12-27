package policyserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// Request from CA to policy server
type Request struct {
	Token      string            `json:"token"`
	Connection policy.Connection `json:"connection"`
}

// Response from policy server to CA
type Response struct {
	CertParams ca.CertParams `json:"certParams"`
	Policy     policy.Policy `json:"policy"`
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
	// Returns:
	// - *Response: Certificate parameters and policy if authorized
	// - error: If authorization denied
	//
	// Error handling:
	// - Return ErrForbidden (403) if access denied by policy
	// - Return other errors (500) for internal errors
	Evaluate(identity string, conn policy.Connection) (*Response, error)
}

// TokenValidator validates authentication tokens and extracts identity.
// Used by handlers to authenticate requests before policy evaluation.
type TokenValidator interface {
	// ValidateAndExtractIdentity validates the token and returns the identity.
	// Returns an error if the token is invalid or expired.
	ValidateAndExtractIdentity(token string) (identity string, err error)
}

// Standard errors for policy evaluation
var (
	// ErrUnauthorized indicates token is invalid or expired (401)
	ErrUnauthorized = &PolicyError{StatusCode: http.StatusUnauthorized, Message: "Unauthorized"}

	// ErrForbidden indicates token valid but access denied by policy (403)
	ErrForbidden = &PolicyError{StatusCode: http.StatusForbidden, Message: "Forbidden"}

	// ErrNotHandled indicates this policy server does not handle the connection (422)
	ErrNotHandled = &PolicyError{StatusCode: http.StatusUnprocessableEntity, Message: "connection not handled"}
)

// PolicyError represents a policy evaluation error with HTTP status code
type PolicyError struct {
	StatusCode int
	Message    string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("policy error %d: %s", e.StatusCode, e.Message)
}

// Unauthorized returns a 401 error with the given message
func Unauthorized(message string) error {
	return &PolicyError{StatusCode: http.StatusUnauthorized, Message: message}
}

// Forbidden returns a 403 error with the given message
func Forbidden(message string) error {
	return &PolicyError{StatusCode: http.StatusForbidden, Message: message}
}

// InternalError returns a 500 error with the given message
func InternalError(message string) error {
	return &PolicyError{StatusCode: http.StatusInternalServerError, Message: message}
}

// NotHandled returns a 422 error indicating this policy server does not handle
// the requested connection. The CA will return 422 to the client.
func NotHandled(message string) error {
	return &PolicyError{StatusCode: http.StatusUnprocessableEntity, Message: message}
}

// Config configures the policy server HTTP handler
type Config struct {
	// CAPublicKey is the CA's SSH public key for verifying request signatures.
	// If empty, signature verification is skipped (not recommended for production).
	CAPublicKey sshcert.RawPublicKey

	// Validator validates tokens and extracts identity (authentication)
	Validator TokenValidator

	// Evaluator makes authorization decisions based on identity
	Evaluator PolicyEvaluator

	// MaxRequestSize limits the request body size (default: 8192 bytes)
	MaxRequestSize int64

	// DiscoveryHash is the content-addressable hash for the Link header.
	// If empty, no Link header is set.
	// The path is hardcoded to "/d/" + hash.
	DiscoveryHash string
}

// handler holds the config and implements the HTTP handler methods
type handler struct {
	config Config
}

// NewHandler creates an HTTP handler for the policy server.
// The handler:
// 1. Parses the request body (token, connection)
// 2. Verifies the CA signature from Authorization header (if CAPublicKey provided)
// 3. Calls the evaluator to make authorization decision
// 4. Returns appropriate HTTP response (200 with policy, or error)
func NewHandler(config Config) http.HandlerFunc {
	if config.MaxRequestSize == 0 {
		config.MaxRequestSize = 8192 // Default from caserver
	}
	h := &handler{config: config}
	return h.ServeHTTP
}

// ServeHTTP handles the policy server request
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse request body
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

	// Verify CA signature if configured (signature is over the entire body)
	if h.config.CAPublicKey != "" {
		// Extract signature from Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			h.writeError(w, http.StatusUnauthorized, "Missing Authorization header")
			return
		}
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			h.writeError(w, http.StatusUnauthorized, "Authorization header must use Bearer scheme")
			return
		}
		signature := strings.TrimPrefix(auth, prefix)
		if signature == "" {
			h.writeError(w, http.StatusUnauthorized, "Empty Bearer token in Authorization header")
			return
		}

		// Verify signature against body bytes
		if err := ca.Verify(h.config.CAPublicKey, string(body), signature); err != nil {
			h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid CA signature: %v", err))
			return
		}
	}

	// Decode the base64url-encoded token
	// Tokens are always base64url encoded by the broker to preserve arbitrary bytes
	decodedToken, err := base64.RawURLEncoding.DecodeString(req.Token)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid token encoding: %v", err))
		return
	}

	// Validate token and extract identity (authentication)
	identity, err := h.config.Validator.ValidateAndExtractIdentity(string(decodedToken))
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Invalid token: %v", err))
		return
	}

	// Evaluate policy based on identity (authorization)
	resp, err := h.config.Evaluator.Evaluate(identity, req.Connection)
	if err != nil {
		// Check if it's a PolicyError with specific status code
		if policyErr, ok := err.(*PolicyError); ok {
			h.writeError(w, policyErr.StatusCode, policyErr.Message)
			return
		}
		// Default to 500 for unknown errors
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Success: return policy response
	h.writeJSON(w, http.StatusOK, resp)
}

// setDiscoveryHeader sets the Link header for discovery if configured.
// Always points to /d/current which redirects to the content-addressed URL.
func (h *handler) setDiscoveryHeader(w http.ResponseWriter) {
	if h.config.DiscoveryHash != "" {
		w.Header().Set("Link", "</d/current>; rel=\"discovery\"")
	}
}

// writeError writes an error response as plain text
func (h *handler) writeError(w http.ResponseWriter, statusCode int, message string) {
	h.setDiscoveryHeader(w)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

// writeJSON writes a JSON response
func (h *handler) writeJSON(w http.ResponseWriter, statusCode int, data any) {
	body, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal response: %v", err))
		return
	}

	h.setDiscoveryHeader(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(body)
}
