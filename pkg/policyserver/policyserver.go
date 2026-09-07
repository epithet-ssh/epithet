package policyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// PolicyEvaluator makes authorization decisions based on inventory ID and connection details.
// The handler trusts normalized authentication facts supplied by the CA.
// Implementations must:
// - Make authorization decision (allow/deny) based on identity
// - Return certificate parameters (principals, expiration, extensions) for the matching host pattern
// - Return appropriate errors for different failure modes
type PolicyEvaluator interface {
	// Evaluate makes an authorization decision using validated, CA-supplied
	// directory and host facts. It has no inventory access.
	// authExpiry is the verified authentication expiry, used to clamp the issued
	// certificate's validity so it can never outlive the auth session that
	// requested it.
	// Returns:
	// - *wire.PolicyResponse: Certificate parameters and policy if authorized
	// - error: If authorization denied
	//
	// Error handling:
	// - Return policyserver.Forbidden (403) if access denied by policy
	// - Return other errors (500) for internal errors
	Evaluate(ctx context.Context, userID string, authExpiry time.Time, conn policy.Connection, facts *inventoryapi.Resolution) (*wire.PolicyResponse, error)
}

// Forbidden returns a 403 error with the given message.
func Forbidden(message string) error {
	return &wire.PolicyError{StatusCode: http.StatusForbidden, Message: message}
}

// Config configures the policy server HTTP handler.
type Config struct {
	// CAPublicKey is the CA's SSH public key, used to verify the request-bound
	// JWT (pkg/serviceauth) on every request. Required.
	CAPublicKey sshcert.RawPublicKey

	Evaluator PolicyEvaluator
}

// handler holds the config and implements the HTTP handler methods.
type handler struct {
	config   Config
	verifier *serviceauth.Verifier
}

// NewHandler creates an HTTP handler for the policy server.
// The handler supports:
//
//	POST / — evaluates a cert request (normalized facts + connection)
//
// Every request must carry a valid CA-minted request token (pkg/serviceauth);
// CAPublicKey is therefore required.
func NewHandler(config Config) (http.Handler, error) {
	if config.CAPublicKey == "" {
		return nil, fmt.Errorf("CAPublicKey is required")
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
	body, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxBodySize+1))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to read request: %v", err))
		return
	}
	defer r.Body.Close()

	// Check if request body exceeds the limit before verification to report a
	// distinct "too large" error instead of a confusing verification failure.
	if len(body) > wire.MaxBodySize {
		h.writeError(w, http.StatusRequestEntityTooLarge, "Request body too large")
		return
	}

	// GET requests read back an empty (non-nil) slice, which hashes
	// identically to the nil body the CA signed over for that request.
	// Verify takes r itself (not just the header) to check the htm/htu
	// claims against the method and target actually received.
	if err := h.verifier.Verify(r, body); err != nil {
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("request verification failed: %v", err))
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.handleCertRequest(w, r, body)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleCertRequest processes a cert evaluation request. body was already
// read (and verified) by ServeHTTP.
func (h *handler) handleCertRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	var req wire.PolicyRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	if err := dec.Decode(new(any)); err != io.EOF {
		h.writeError(w, http.StatusBadRequest, "invalid trailing JSON")
		return
	}
	if err := req.Facts.Validate(hostpattern.NormalizeName(req.Connection.RemoteHost)); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Evaluate policy based on identity (authorization).
	resp, err := h.config.Evaluator.Evaluate(r.Context(), req.Facts.Authentication.ID, req.Facts.Authentication.ExpiresAt, req.Connection, req.Facts)
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
