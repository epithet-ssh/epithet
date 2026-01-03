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

	// DiscoveryHash is the content-addressable hash for discovery (authenticated)
	DiscoveryHash string

	// BootstrapHash is the content-addressable hash for bootstrap (unauthenticated)
	BootstrapHash string

	// AuthConfig is the bootstrap auth configuration to return
	AuthConfig BootstrapAuth
}

// Discovery is the response format for the discovery endpoint
type Discovery struct {
	MatchPatterns []string `json:"matchPatterns"`
}

// contentHandler handles both bootstrap and discovery content-addressed endpoints.
// It determines which content to serve based on matching the URL hash against known hashes.
type contentHandler struct {
	config DiscoveryConfig
}

// NewDiscoveryHandler creates an HTTP handler for the /d/<hash> content-addressed endpoints.
// The handler:
// - For bootstrap hash: Returns auth config (no authentication required)
// - For discovery hash: Validates Bearer token and returns match patterns
// - For unknown hashes: Returns 404 (forces clients to follow redirect)
// Sets Cache-Control: immutable for aggressive caching.
func NewDiscoveryHandler(config DiscoveryConfig) http.HandlerFunc {
	h := &contentHandler{config: config}
	return h.ServeHTTP
}

// NewDiscoveryRedirectHandler returns a handler that redirects to the content-addressed discovery URL.
// The redirect response is cached for 5 minutes to allow policy changes to propagate.
// Clients should request /d/current and follow the redirect to /d/{hash}.
// Uses 302 Found (temporary) rather than 301 (permanent) since the redirect target may change.
// If baseURL is set, redirects to an absolute URL on that base; otherwise uses relative URLs.
func NewDiscoveryRedirectHandler(hash string, baseURL string) http.HandlerFunc {
	location := "/d/" + hash
	if baseURL != "" {
		location = strings.TrimSuffix(baseURL, "/") + "/d/" + hash
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	}
}

// NewBootstrapRedirectHandler returns a handler that redirects to the content-addressed bootstrap URL.
// The redirect response is cached for 5 minutes to allow config changes to propagate.
// Clients should request /d/bootstrap and follow the redirect to /d/{hash}.
// Uses 302 Found (temporary) rather than 301 (permanent) since the redirect target may change.
// If baseURL is set, redirects to an absolute URL on that base; otherwise uses relative URLs.
func NewBootstrapRedirectHandler(hash string, baseURL string) http.HandlerFunc {
	location := "/d/" + hash
	if baseURL != "" {
		location = strings.TrimSuffix(baseURL, "/") + "/d/" + hash
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	}
}

// ServeHTTP handles content-addressed requests for both bootstrap and discovery.
func (h *contentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept GET
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract hash from URL path: /d/{hash} or /d/{hash}/
	path := strings.TrimPrefix(r.URL.Path, "/d/")
	path = strings.TrimSuffix(path, "/")
	hash := path

	// Route based on hash match
	switch hash {
	case h.config.BootstrapHash:
		h.serveBootstrap(w, r)
	case h.config.DiscoveryHash:
		h.serveDiscovery(w, r)
	default:
		// Unknown hash - return 404 to force client to follow redirect
		h.writeError(w, http.StatusNotFound, "Unknown discovery hash")
	}
}

// serveBootstrap serves the bootstrap auth config (no authentication required).
func (h *contentHandler) serveBootstrap(w http.ResponseWriter, r *http.Request) {
	bootstrap := Bootstrap{
		Auth: h.config.AuthConfig,
	}

	body, err := json.Marshal(bootstrap)
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

// serveDiscovery serves the discovery match patterns (authentication required).
func (h *contentHandler) serveDiscovery(w http.ResponseWriter, r *http.Request) {
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

	body, err := json.Marshal(discovery)
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

// writeError writes an error response
func (h *contentHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}
