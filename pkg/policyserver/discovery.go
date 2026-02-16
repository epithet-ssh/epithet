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

	// UnauthHash is the content-addressable hash for unauthenticated discovery (auth config only)
	UnauthHash string

	// AuthHash is the content-addressable hash for authenticated discovery (auth config + match patterns)
	AuthHash string

	// AuthConfig is the auth configuration to return
	AuthConfig BootstrapAuth
}

// Discovery is the unified response format for the discovery endpoint.
// Unauthenticated: returns Auth only. Authenticated: returns Auth + MatchPatterns.
type Discovery struct {
	Auth          *BootstrapAuth `json:"auth,omitempty"`
	MatchPatterns []string       `json:"matchPatterns,omitempty"`
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

// NewDiscoveryRedirectHandler returns an auth-aware handler that redirects to the
// content-addressed discovery URL. Unauthenticated requests redirect to unauthHash
// (auth config only); authenticated requests redirect to authHash (auth config + match patterns).
// Sets Vary: Authorization so caches don't serve the wrong response.
// Uses 302 Found (temporary) since the redirect target may change.
func NewDiscoveryRedirectHandler(unauthHash, authHash, baseURL string) http.HandlerFunc {
	unauthLocation := "/d/" + unauthHash
	authLocation := "/d/" + authHash
	if baseURL != "" {
		base := strings.TrimSuffix(baseURL, "/")
		unauthLocation = base + "/d/" + unauthHash
		authLocation = base + "/d/" + authHash
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Vary", "Authorization")
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("Location", authLocation)
		} else {
			w.Header().Set("Location", unauthLocation)
		}
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

	// Route based on hash match.
	switch hash {
	case h.config.UnauthHash:
		h.serveUnauthDiscovery(w)
	case h.config.AuthHash:
		h.serveAuthDiscovery(w, r)
	default:
		// Unknown hash - return 404 to force client to follow redirect.
		h.writeError(w, http.StatusNotFound, "Unknown discovery hash")
	}
}

// serveUnauthDiscovery serves the auth config (no authentication required).
func (h *contentHandler) serveUnauthDiscovery(w http.ResponseWriter) {
	authConfig := h.config.AuthConfig
	discovery := Discovery{
		Auth: &authConfig,
	}

	body, err := json.Marshal(discovery)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to marshal response")
		return
	}

	// Content-addressable URL = immutable caching.
	w.Header().Set("Cache-Control", "max-age=31536000, immutable")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// serveAuthDiscovery serves auth config + match patterns (authentication required).
func (h *contentHandler) serveAuthDiscovery(w http.ResponseWriter, r *http.Request) {
	// Parse Bearer token from Authorization header.
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

	// Decode base64url-encoded token (broker encodes tokens for binary safety).
	decodedToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid token encoding")
		return
	}

	// Validate token (we don't need the identity for discovery, just auth).
	if _, err := h.config.Validator.ValidateAndExtractIdentity(string(decodedToken)); err != nil {
		h.writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Return full discovery data (auth config + match patterns).
	authConfig := h.config.AuthConfig
	discovery := Discovery{
		Auth:          &authConfig,
		MatchPatterns: h.config.MatchPatterns,
	}

	body, err := json.Marshal(discovery)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to marshal response")
		return
	}

	// Content-addressable URL = immutable caching.
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
