package policyserver

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// DiscoveryConfig configures the discovery handler
type DiscoveryConfig struct {
	// Validator validates Bearer tokens and extracts identity
	Validator TokenValidator

	// MatchPatterns are the host patterns to return
	MatchPatterns []string

	// Hash is the content-addressable hash (for verification, not currently used)
	Hash string
}

// Discovery is the response format for the discovery endpoint
type Discovery struct {
	MatchPatterns []string `json:"matchPatterns"`
}

// discoveryHandler holds the config and implements the HTTP handler
type discoveryHandler struct {
	config DiscoveryConfig
}

// NewDiscoveryHandler creates an HTTP handler for the discovery endpoint.
// The handler:
// 1. Validates the Bearer token via the evaluator
// 2. Returns the match patterns as JSON
// 3. Sets Cache-Control: immutable for aggressive caching
func NewDiscoveryHandler(config DiscoveryConfig) http.HandlerFunc {
	h := &discoveryHandler{config: config}
	return h.ServeHTTP
}

// NewDiscoveryRedirectHandler returns a handler that redirects to the content-addressed discovery URL.
// The redirect response is cached for 5 minutes to allow policy changes to propagate.
// Clients should request /d/current and follow the redirect to /d/{hash}.
// Uses 302 Found (temporary) rather than 301 (permanent) since the redirect target may change.
func NewDiscoveryRedirectHandler(hash string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Location", "/d/"+hash)
		w.WriteHeader(http.StatusFound)
	}
}

// ServeHTTP handles the discovery request
func (h *discoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept GET
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Parse Bearer token from Authorization header
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

	token := strings.TrimPrefix(auth, prefix)
	if token == "" {
		h.writeError(w, http.StatusUnauthorized, "Empty Bearer token")
		return
	}

	// Decode base64url-encoded token (broker encodes tokens for binary safety)
	decodedToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid token encoding")
		return
	}

	// Validate token (we don't need the identity for discovery, just auth)
	if _, err := h.config.Validator.ValidateAndExtractIdentity(string(decodedToken)); err != nil {
		h.writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Return discovery data
	discovery := Discovery{
		MatchPatterns: h.config.MatchPatterns,
	}

	h.writeJSON(w, discovery)
}

// writeError writes an error response
func (h *discoveryHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

// writeJSON writes the discovery response with caching headers
func (h *discoveryHandler) writeJSON(w http.ResponseWriter, data Discovery) {
	body, err := json.Marshal(data)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to marshal response")
		return
	}

	// Content-addressable URL = immutable caching
	w.Header().Set("Cache-Control", "max-age=31536000, immutable")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
