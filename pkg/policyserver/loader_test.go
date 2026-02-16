package policyserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

func TestPolicyLoader_LoadFromFile_YAML(t *testing.T) {
	// Create a temporary YAML policy file.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	content := `
users:
  alice@example.com:
    - admin
  bob@example.com:
    - user
defaults:
  allow:
    root:
      - admin
  expiration: "10m"
hosts:
  "*.example.com": {}
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	loader := policyserver.NewPolicyLoader(policyFile)
	policy, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	// Verify users.
	if len(policy.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(policy.Users))
	}
	if tags, ok := policy.Users["alice@example.com"]; !ok || len(tags) != 1 || tags[0] != "admin" {
		t.Errorf("unexpected alice tags: %v", tags)
	}

	// Verify defaults.
	if policy.Defaults == nil {
		t.Fatal("expected defaults to be set")
	}
	if policy.Defaults.Expiration != "10m" {
		t.Errorf("expected expiration 10m, got %s", policy.Defaults.Expiration)
	}

	// Verify hosts.
	if len(policy.Hosts) != 1 {
		t.Errorf("expected 1 host pattern, got %d", len(policy.Hosts))
	}
}

func TestPolicyLoader_LoadFromFile_CUE(t *testing.T) {
	// Create a temporary CUE policy file.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.cue")

	content := `
users: {
	"alice@example.com": ["admin"]
	"bob@example.com": ["user"]
}
defaults: {
	allow: {
		root: ["admin"]
	}
	expiration: "10m"
}
hosts: {
	"*.example.com": {}
}
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	loader := policyserver.NewPolicyLoader(policyFile)
	policy, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	// Verify users.
	if len(policy.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(policy.Users))
	}
	if tags, ok := policy.Users["alice@example.com"]; !ok || len(tags) != 1 || tags[0] != "admin" {
		t.Errorf("unexpected alice tags: %v", tags)
	}

	// Verify defaults.
	if policy.Defaults == nil {
		t.Fatal("expected defaults to be set")
	}
	if policy.Defaults.Expiration != "10m" {
		t.Errorf("expected expiration 10m, got %s", policy.Defaults.Expiration)
	}

	// Verify hosts.
	if len(policy.Hosts) != 1 {
		t.Errorf("expected 1 host pattern, got %d", len(policy.Hosts))
	}
}

func TestPolicyLoader_LoadFromFile_JSON(t *testing.T) {
	// Create a temporary JSON policy file.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.json")

	policy := map[string]any{
		"users": map[string][]string{
			"alice@example.com": {"admin"},
		},
		"hosts": map[string]any{
			"server1": map[string]any{},
		},
	}
	content, _ := json.Marshal(policy)
	if err := os.WriteFile(policyFile, content, 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	loader := policyserver.NewPolicyLoader(policyFile)
	loaded, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	if len(loaded.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(loaded.Users))
	}
	if len(loaded.Hosts) != 1 {
		t.Errorf("expected 1 host, got %d", len(loaded.Hosts))
	}
}

func TestPolicyLoader_LoadFromHTTP(t *testing.T) {
	// Create a test HTTP server.
	policy := map[string]any{
		"users": map[string][]string{
			"alice@example.com": {"admin"},
		},
		"hosts": map[string]any{
			"server1": map[string]any{},
		},
	}
	content, _ := json.Marshal(policy)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(content)
	}))
	defer server.Close()

	loader := policyserver.NewPolicyLoader(server.URL)
	loaded, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	if len(loaded.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(loaded.Users))
	}
}

func TestPolicyLoader_FileScheme(t *testing.T) {
	// Create a temporary policy file.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	content := `
users:
  alice@example.com:
    - admin
hosts:
  "*": {}
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Load using file:// scheme.
	loader := policyserver.NewPolicyLoader("file://" + policyFile)
	loaded, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	if len(loaded.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(loaded.Users))
	}
}

func TestPolicyLoader_FileCaching(t *testing.T) {
	// Create a temporary policy file.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	content := `
users:
  alice@example.com:
    - admin
hosts:
  "*": {}
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	loader := policyserver.NewPolicyLoader(policyFile)

	// Load twice - second load should use cache.
	policy1, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("first load failed: %v", err)
	}

	policy2, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("second load failed: %v", err)
	}

	// Both should return the same object (cached).
	if policy1 != policy2 {
		t.Error("expected cached policy to be returned")
	}

	// Now modify the file (with a slight delay to ensure mtime changes).
	time.Sleep(10 * time.Millisecond)
	newContent := `
users:
  alice@example.com:
    - admin
  bob@example.com:
    - user
hosts:
  "*": {}
`
	if err := os.WriteFile(policyFile, []byte(newContent), 0644); err != nil {
		t.Fatalf("failed to update policy file: %v", err)
	}

	// Load again - should get new policy.
	policy3, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("third load failed: %v", err)
	}

	if len(policy3.Users) != 2 {
		t.Errorf("expected 2 users after update, got %d", len(policy3.Users))
	}
}

func TestPolicyLoader_InvalidPolicy(t *testing.T) {
	// Create a policy file with invalid expiration.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	content := `
users:
  alice@example.com:
    - admin
defaults:
  expiration: "invalid"
hosts:
  "*": {}
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	loader := policyserver.NewPolicyLoader(policyFile)
	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid expiration, got nil")
	}
}

func TestPolicyLoader_HTTPError(t *testing.T) {
	// Create a test server that returns 500.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	loader := policyserver.NewPolicyLoader(server.URL)
	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestPolicyLoader_FileNotFound(t *testing.T) {
	loader := policyserver.NewPolicyLoader("/nonexistent/path/policy.yaml")
	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestPolicyConfig_AuthDiscoveryHash(t *testing.T) {
	auth := policyserver.BootstrapAuth{Type: "oidc", Issuer: "https://example.com", ClientID: "test"}

	policy1 := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"server1": {},
			"server2": {},
		},
	}

	policy2 := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"server2": {},
			"server1": {},
		},
	}

	// Same hosts, different order - should have same hash.
	hash1 := policyserver.ComputeAuthDiscoveryHash(auth, policy1.HostPatterns())
	hash2 := policyserver.ComputeAuthDiscoveryHash(auth, policy2.HostPatterns())
	if hash1 != hash2 {
		t.Error("expected same hash for same hosts in different order")
	}

	// Different hosts - should have different hash.
	policy3 := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"server1": {},
		},
	}

	hash3 := policyserver.ComputeAuthDiscoveryHash(auth, policy3.HostPatterns())
	if hash1 == hash3 {
		t.Error("expected different hash for different hosts")
	}
}

func TestPolicyConfig_HostPatterns(t *testing.T) {
	policy := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"*.example.com": {},
			"prod-*":        {},
		},
	}

	patterns := policy.HostPatterns()
	if len(patterns) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(patterns))
	}
}

func TestStaticProvider(t *testing.T) {
	policy := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
	}

	provider := policyserver.NewStaticProvider(policy)
	loaded, err := provider.GetPolicy(context.Background())
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}

	if loaded != policy {
		t.Error("expected same policy object")
	}
}

func TestLoaderProvider(t *testing.T) {
	// Create a temporary policy file.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")

	content := `
users:
  alice@example.com:
    - admin
hosts:
  "*": {}
`
	if err := os.WriteFile(policyFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	loader := policyserver.NewPolicyLoader(policyFile)
	provider := policyserver.NewLoaderProvider(loader)

	loaded, err := provider.GetPolicy(context.Background())
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}

	if len(loaded.Users) != 1 {
		t.Errorf("expected 1 user, got %d", len(loaded.Users))
	}
}
