package policyserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// Request from CA to policy server
type Request struct {
	Token      string            `json:"token"`
	Signature  string            `json:"signature"`
	Connection policy.Connection `json:"connection"`
}

// Response from policy server to CA
type Response struct {
	CertParams ca.CertParams `json:"certParams"`
	Policy     policy.Policy `json:"policy"`
}

// PolicyEvaluator makes authorization decisions based on token and connection details.
// Implementations must:
// - Validate the authentication token (e.g., verify OIDC JWT signature)
// - Make authorization decision (allow/deny)
// - Return certificate parameters (principals, expiration, extensions) and policy (hostPattern)
// - Return appropriate errors for different failure modes
type PolicyEvaluator interface {
	// Evaluate makes an authorization decision for the given token and connection.
	// Returns:
	// - *Response: Certificate parameters and policy if authorized
	// - error: If authorization denied or validation failed
	//
	// Error handling:
	// - Return ErrUnauthorized (401) if token is invalid/expired
	// - Return ErrForbidden (403) if token valid but access denied by policy
	// - Return other errors (500) for internal errors
	Evaluate(token string, conn policy.Connection) (*Response, error)
}

// Standard errors for policy evaluation
var (
	// ErrUnauthorized indicates token is invalid or expired (401)
	ErrUnauthorized = &PolicyError{StatusCode: http.StatusUnauthorized, Message: "Unauthorized"}

	// ErrForbidden indicates token valid but access denied by policy (403)
	ErrForbidden = &PolicyError{StatusCode: http.StatusForbidden, Message: "Forbidden"}
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

// Config configures the policy server HTTP handler
type Config struct {
	// CAPublicKey is the CA's SSH public key for verifying request signatures.
	// If empty, signature verification is skipped (not recommended for production).
	CAPublicKey sshcert.RawPublicKey

	// Evaluator makes authorization decisions
	Evaluator PolicyEvaluator

	// MaxRequestSize limits the request body size (default: 8192 bytes)
	MaxRequestSize int64
}

// NewHandler creates an HTTP handler for the policy server.
// The handler:
// 1. Parses the request body (token, signature, connection)
// 2. Verifies the CA signature (if CAPublicKey provided)
// 3. Calls the evaluator to make authorization decision
// 4. Returns appropriate HTTP response (200 with policy, or error)
func NewHandler(config Config) http.HandlerFunc {
	maxRequestSize := config.MaxRequestSize
	if maxRequestSize == 0 {
		maxRequestSize = 8192 // Default from caserver
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		// Parse request body
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestSize))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to read request: %v", err))
			return
		}
		defer r.Body.Close()

		var req Request
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
			return
		}

		// Verify CA signature if configured
		if config.CAPublicKey != "" {
			if err := ca.Verify(config.CAPublicKey, req.Token, req.Signature); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid CA signature: %v", err))
				return
			}
		}

		// Evaluate policy
		resp, err := config.Evaluator.Evaluate(req.Token, req.Connection)
		if err != nil {
			// Check if it's a PolicyError with specific status code
			if policyErr, ok := err.(*PolicyError); ok {
				writeError(w, policyErr.StatusCode, policyErr.Message)
				return
			}
			// Default to 500 for unknown errors
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Success: return policy response
		writeJSON(w, http.StatusOK, resp)
	}
}

// writeError writes an error response as plain text
func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data any) {
	body, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to marshal response: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(body)
}
