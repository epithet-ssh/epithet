package policyserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/encoding/yaml"
	"github.com/gregjones/httpcache"
)

// PolicyConfig contains the dynamic policy data that can be loaded from a URL.
// This includes users, defaults, and hosts that can change without restarting the server.
type PolicyConfig struct {
	Users    map[string][]string    `yaml:"users" json:"users"`       // user identity → tags
	Defaults *DefaultPolicy         `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Hosts    map[string]*HostPolicy `yaml:"hosts,omitempty" json:"hosts,omitempty"` // hostname → host policy
}

// Validate checks that the PolicyConfig is valid.
func (c *PolicyConfig) Validate() error {
	if c.Users == nil {
		return fmt.Errorf("users is required")
	}

	// Validate default expiration if provided.
	if c.Defaults != nil && c.Defaults.Expiration != "" {
		if err := ValidateDuration(c.Defaults.Expiration); err != nil {
			return fmt.Errorf("invalid defaults.expiration: %w", err)
		}
	}

	// Validate host policy expirations.
	for hostname, hostPolicy := range c.Hosts {
		if hostPolicy.Expiration != "" {
			if err := ValidateDuration(hostPolicy.Expiration); err != nil {
				return fmt.Errorf("invalid expiration for host %s: %w", hostname, err)
			}
		}
	}

	return nil
}

// HostPatterns returns the list of host patterns defined in the policy.
func (c *PolicyConfig) HostPatterns() []string {
	patterns := make([]string, 0, len(c.Hosts))
	for pattern := range c.Hosts {
		patterns = append(patterns, pattern)
	}
	return patterns
}

// PolicyLoader loads policy configuration from a URL (file or HTTP).
// It handles caching for both HTTP (via Cache-Control headers) and file sources (via mtime).
type PolicyLoader struct {
	url        string
	httpClient *http.Client

	// File caching state.
	mu           sync.RWMutex
	cachedPolicy *PolicyConfig
	cachedMtime  time.Time
}

// NewPolicyLoader creates a new policy loader for the given URL.
// Supports:
//   - http:// or https:// - HTTP fetch with automatic caching based on response headers
//   - file:///path - explicit file path
//   - /path or ./path - bare file path
func NewPolicyLoader(url string) *PolicyLoader {
	// Create HTTP client with caching transport.
	transport := httpcache.NewMemoryCacheTransport()
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &PolicyLoader{
		url:        url,
		httpClient: httpClient,
	}
}

// Load loads the policy configuration from the configured URL.
// For HTTP sources, caching is handled by httpcache respecting Cache-Control headers.
// For file sources, the policy is reloaded if the file's mtime has changed.
func (l *PolicyLoader) Load(ctx context.Context) (*PolicyConfig, error) {
	url := l.url

	// Determine the source type and load accordingly.
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return l.loadFromHTTP(ctx, url)
	}

	// Handle file:// scheme.
	if strings.HasPrefix(url, "file://") {
		path := strings.TrimPrefix(url, "file://")
		return l.loadFromFile(path)
	}

	// Bare path (absolute or relative).
	return l.loadFromFile(url)
}

// loadFromHTTP fetches policy from an HTTP URL.
// Caching is handled by the httpcache transport which respects Cache-Control headers.
func (l *PolicyLoader) loadFromHTTP(ctx context.Context, url string) (*PolicyConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch policy from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch policy from %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy from %s: %w", url, err)
	}

	// Detect format from Content-Type header.
	contentType := resp.Header.Get("Content-Type")
	return l.parsePolicy(body, contentType, url)
}

// loadFromFile loads policy from a file path.
// Uses mtime-based caching to avoid re-parsing unchanged files.
func (l *PolicyLoader) loadFromFile(path string) (*PolicyConfig, error) {
	// Get file info for mtime check.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat policy file %s: %w", path, err)
	}
	mtime := info.ModTime()

	// Check cache.
	l.mu.RLock()
	if l.cachedPolicy != nil && l.cachedMtime.Equal(mtime) {
		policy := l.cachedPolicy
		l.mu.RUnlock()
		return policy, nil
	}
	l.mu.RUnlock()

	// Need to reload.
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	// Detect format from file extension.
	ext := strings.ToLower(filepath.Ext(path))
	contentType := extensionToContentType(ext)

	policy, err := l.parsePolicy(body, contentType, path)
	if err != nil {
		return nil, err
	}

	// Update cache.
	l.mu.Lock()
	l.cachedPolicy = policy
	l.cachedMtime = mtime
	l.mu.Unlock()

	return policy, nil
}

// parsePolicy parses policy data using CUE as the unified parser.
// CUE natively handles JSON and CUE syntax; YAML is converted via cue/encoding/yaml.
func (l *PolicyLoader) parsePolicy(data []byte, contentType, source string) (*PolicyConfig, error) {
	ctx := cuecontext.New()

	// Normalize content type (remove charset etc).
	contentType = normalizeContentType(contentType)

	var value cue.Value

	switch contentType {
	case "application/x-yaml", "text/yaml", "text/x-yaml":
		// Use CUE's YAML parser.
		file, err := yaml.Extract(source, data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML policy from %s: %w", source, err)
		}
		value = ctx.BuildFile(file)
	case "application/json", "application/cue", "":
		// CUE can parse both JSON and CUE natively.
		// Default to CUE/JSON parsing for unknown content types.
		value = ctx.CompileBytes(data, cue.Filename(source))
	default:
		// Try CUE/JSON parsing as fallback.
		value = ctx.CompileBytes(data, cue.Filename(source))
	}

	if err := value.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse policy from %s: %w", source, err)
	}

	// Validate the CUE value is concrete.
	if err := value.Validate(cue.Concrete(true)); err != nil {
		return nil, fmt.Errorf("policy validation failed for %s: %w", source, err)
	}

	// Decode into PolicyConfig.
	var policy PolicyConfig
	if err := value.Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to decode policy from %s: %w", source, err)
	}

	// Initialize Users map if nil.
	if policy.Users == nil {
		policy.Users = make(map[string][]string)
	}

	// Validate the loaded policy.
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy from %s: %w", source, err)
	}

	return &policy, nil
}

// extensionToContentType maps file extensions to content types.
func extensionToContentType(ext string) string {
	switch ext {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/x-yaml"
	case ".cue":
		return "application/cue"
	default:
		return "" // Will default to YAML.
	}
}

// normalizeContentType extracts the media type from a content-type header.
func normalizeContentType(contentType string) string {
	// Handle "application/json; charset=utf-8" -> "application/json".
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}
	return strings.TrimSpace(strings.ToLower(contentType))
}

// PolicyProvider is the interface for getting the current policy.
// This allows the evaluator to get fresh policy on each request.
type PolicyProvider interface {
	// GetPolicy returns the current policy configuration.
	// Implementations should handle caching internally.
	GetPolicy(ctx context.Context) (*PolicyConfig, error)
}

// LoaderProvider wraps a PolicyLoader to implement PolicyProvider.
type LoaderProvider struct {
	loader *PolicyLoader
}

// NewLoaderProvider creates a PolicyProvider that uses a PolicyLoader.
func NewLoaderProvider(loader *PolicyLoader) *LoaderProvider {
	return &LoaderProvider{loader: loader}
}

// GetPolicy loads the current policy from the configured URL.
func (p *LoaderProvider) GetPolicy(ctx context.Context) (*PolicyConfig, error) {
	return p.loader.Load(ctx)
}

// StaticProvider provides a fixed policy configuration.
// Used for backwards compatibility when policy is defined inline in config.
type StaticProvider struct {
	policy *PolicyConfig
}

// NewStaticProvider creates a PolicyProvider that always returns the same policy.
func NewStaticProvider(policy *PolicyConfig) *StaticProvider {
	return &StaticProvider{policy: policy}
}

// GetPolicy returns the static policy configuration.
func (p *StaticProvider) GetPolicy(ctx context.Context) (*PolicyConfig, error) {
	return p.policy, nil
}
