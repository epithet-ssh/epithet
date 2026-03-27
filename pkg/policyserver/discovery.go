package policyserver

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// DiscoveryConfig configures the discovery handler.
type DiscoveryConfig struct {
	// Validator validates Bearer tokens and extracts identity.
	Validator TokenValidator

	// MatchPatterns are the host patterns to return for authenticated requests.
	MatchPatterns []string

	// AuthConfig is the auth configuration to return.
	AuthConfig BootstrapAuth
}

// Discovery is the unified response format for the discovery endpoint.
// Unauthenticated: returns Auth only. Authenticated: returns Auth + MatchPatterns.
type Discovery struct {
	Auth          *BootstrapAuth `json:"auth,omitempty"`
	MatchPatterns []string       `json:"matchPatterns,omitempty"`
}

// NewDiscoveryHandler creates an HTTP handler for the /discovery discovery endpoint.
// The handler serves content directly using Vary: Authorization for cache discrimination:
//   - Without Authorization header: returns auth config only (no authentication required)
//   - With Authorization header: validates Bearer token and returns auth config + match patterns
//
// Sets Cache-Control: max-age=300 and Vary: Authorization on all responses.
func NewDiscoveryHandler(config DiscoveryConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
			return
		}

		w.Header().Set("Vary", "Authorization")
		w.Header().Set("Cache-Control", "max-age=300")

		auth := r.Header.Get("Authorization")
		if auth == "" {
			// Unauthenticated: return auth config only.
			authConfig := config.AuthConfig
			writeDiscoveryJSON(w, &Discovery{Auth: &authConfig})
			return
		}

		// Authenticated: validate token and return auth config + match patterns.
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Authorization header must use Bearer scheme"))
			return
		}

		token := strings.TrimPrefix(auth, prefix)
		if token == "" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Empty Bearer token"))
			return
		}

		// Decode base64url-encoded token (broker encodes tokens for binary safety).
		decodedToken, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid token encoding"))
			return
		}

		// Validate token (we don't need the identity for discovery, just auth).
		if _, err := config.Validator.ValidateAndExtractIdentity(string(decodedToken)); err != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}

		authConfig := config.AuthConfig
		writeDiscoveryJSON(w, &Discovery{
			Auth:          &authConfig,
			MatchPatterns: config.MatchPatterns,
		})
	}
}

func writeDiscoveryJSON(w http.ResponseWriter, d *Discovery) {
	body, err := json.Marshal(d)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed to marshal response"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
