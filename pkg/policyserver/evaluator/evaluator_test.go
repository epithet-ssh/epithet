package evaluator_test

import (
	"context"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Note: These tests use mock configs, not real OIDC token validation
// Real OIDC validation is tested in pkg/policyserver/oidc

func TestEvaluateGlobalPolicy_UserInList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that requires OIDC provider")
	}

	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
			"bob@example.com":   {"user"},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"root": {"admin"},
				"app":  {"user"},
			},
		},
	}

	ctx := context.Background()
	eval, _, err := evaluator.New(ctx, cfg, tlsconfig.Config{})
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	// Note: This would fail with a real token - we're just testing the structure
	// Real token validation is tested in integration tests
	_ = eval
}

func TestEvaluateGlobalPolicy_DefaultAllow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that requires OIDC provider")
	}

	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"root":  {"admin"},
				"guest": {"visitor"},
			},
			Expiration: "5m",
		},
	}

	ctx := context.Background()
	eval, _, err := evaluator.New(ctx, cfg, tlsconfig.Config{})
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	_ = eval
}

func TestEvaluateHostPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that requires OIDC provider")
	}

	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"dba"},
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"prod-db-01": {
				Allow: map[string][]string{
					"postgres": {"dba"},
				},
				Expiration: "2m",
			},
		},
	}

	ctx := context.Background()
	eval, _, err := evaluator.New(ctx, cfg, tlsconfig.Config{})
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	_ = eval
}

func TestNew_InvalidOIDCIssuer(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   "https://invalid-oidc-provider.example.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := evaluator.New(ctx, cfg, tlsconfig.Config{})
	if err == nil {
		t.Fatal("expected error for invalid OIDC issuer, got nil")
	}
}

// Unit tests using NewForTesting (no OIDC validation required)

// TestHelloRequest_NoDefaults verifies that Hello requests succeed when only
// host-specific policies exist (no defaults). This was a bug where Hello requests
// failed because isAuthorized couldn't match empty host against host-specific patterns.
func TestHelloRequest_NoDefaults(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"alice@example.com": {"dba"},
		},
		// No Defaults - only host-specific policies
		Hosts: map[string]*policyserver.HostPolicy{
			"prod-db-*": {
				Allow: map[string][]string{
					"postgres": {"dba"},
				},
				Expiration: "2m",
			},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// Hello request has empty connection
	resp, err := eval.Evaluate("alice@example.com", policy.Connection{})
	if err != nil {
		t.Fatalf("Hello request should succeed, got error: %v", err)
	}

	// Should return hostUsers mapping for discovery
	if resp.Policy.HostUsers == nil {
		t.Fatal("expected hostUsers in response")
	}
	if _, ok := resp.Policy.HostUsers["prod-db-*"]; !ok {
		t.Error("expected 'prod-db-*' pattern in hostUsers")
	}
}

// TestHelloRequest_WithDefaults verifies Hello requests work when defaults are merged into host patterns.
// Note: With the new behavior, an explicit host pattern is required - defaults.Allow alone
// does NOT create a wildcard pattern. To match all hosts, add "*": {} to Hosts.
func TestHelloRequest_WithDefaults(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"root": {"admin"},
			},
			Expiration: "5m",
		},
		// Explicit wildcard pattern - defaults.Allow is merged into this
		Hosts: map[string]*policyserver.HostPolicy{
			"*": {},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	resp, err := eval.Evaluate("alice@example.com", policy.Connection{})
	if err != nil {
		t.Fatalf("Hello request should succeed, got error: %v", err)
	}

	if resp.Policy.HostUsers == nil {
		t.Fatal("expected hostUsers in response")
	}
	if _, ok := resp.Policy.HostUsers["*"]; !ok {
		t.Error("expected '*' pattern in hostUsers (from Hosts with defaults merged)")
	}
}

// TestCertRequest_AuthorizationEnforced verifies regular cert requests still check authorization
func TestCertRequest_AuthorizationEnforced(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"alice@example.com": {"dba"},
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"prod-db-*": {
				Allow: map[string][]string{
					"postgres": {"dba"},
				},
			},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// Authorized request should succeed
	_, err := eval.Evaluate("alice@example.com", policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "postgres",
	})
	if err != nil {
		t.Errorf("authorized request should succeed, got error: %v", err)
	}

	// Unauthorized host should fail
	_, err = eval.Evaluate("alice@example.com", policy.Connection{
		RemoteHost: "web-server-01",
		RemoteUser: "postgres",
	})
	if err == nil {
		t.Error("unauthorized host should fail, got nil error")
	}

	// Unauthorized user should fail
	_, err = eval.Evaluate("alice@example.com", policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "root",
	})
	if err == nil {
		t.Error("unauthorized user should fail, got nil error")
	}
}

// TestEvaluate_UnknownUser verifies unknown users are rejected
func TestEvaluate_UnknownUser(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// Unknown user should fail for Hello request
	_, err := eval.Evaluate("unknown@example.com", policy.Connection{})
	if err == nil {
		t.Error("unknown user should fail, got nil error")
	}
}

// TestHelloRequest_UserWithNoAccess verifies Hello rejects users who exist but have no authorized hosts
func TestHelloRequest_UserWithNoAccess(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"alice@example.com": {"guest"}, // Has 'guest' tag but no policies allow 'guest'
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"prod-db-*": {
				Allow: map[string][]string{
					"postgres": {"dba"}, // Only 'dba' tag is allowed
				},
			},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// User exists but has no authorized hosts (their tag doesn't grant access)
	_, err := eval.Evaluate("alice@example.com", policy.Connection{})
	if err == nil {
		t.Error("user with no authorized hosts should fail, got nil error")
	}
}

// TestHostMustMatchPattern_RejectsUnmatchedHost verifies that hosts not matching
// any pattern in Hosts are rejected, even if defaults.Allow would permit them.
func TestHostMustMatchPattern_RejectsUnmatchedHost(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"brianm@skife.org": {"wheel"},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"brianm": {"wheel"},
			},
			Expiration: "5m",
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"v*":   {Allow: map[string][]string{"brianm": {"wheel"}, "arch": {"wheel"}}},
			"badb": {},
			"hati": {},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// "wobble" doesn't match any pattern in Hosts - should be rejected
	_, err := eval.Evaluate("brianm@skife.org", policy.Connection{
		RemoteHost: "wobble",
		RemoteUser: "brianm",
	})
	if err == nil {
		t.Error("expected error for host not matching any pattern, got nil")
	}

	// "v1" matches "v*" - should succeed
	_, err = eval.Evaluate("brianm@skife.org", policy.Connection{
		RemoteHost: "v1",
		RemoteUser: "brianm",
	})
	if err != nil {
		t.Errorf("v1 should match v* pattern, got error: %v", err)
	}

	// "badb" matches exactly - should succeed
	_, err = eval.Evaluate("brianm@skife.org", policy.Connection{
		RemoteHost: "badb",
		RemoteUser: "brianm",
	})
	if err != nil {
		t.Errorf("badb should match exactly, got error: %v", err)
	}
}

// TestDefaultsApplyToMatchedHosts verifies that defaults.Allow applies to hosts
// with empty Allow blocks in their host policy.
func TestDefaultsApplyToMatchedHosts(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"root": {"admin"},
			},
			Expiration: "10m",
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"server1": {}, // Empty - should use defaults.Allow
			"server2": {}, // Empty - should use defaults.Allow
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// server1 with empty Allow should get "root" from defaults
	resp, err := eval.Evaluate("alice@example.com", policy.Connection{
		RemoteHost: "server1",
		RemoteUser: "root",
	})
	if err != nil {
		t.Errorf("server1 as root should succeed via defaults.Allow, got error: %v", err)
	}
	if resp != nil && resp.CertParams.Expiration != 10*time.Minute {
		t.Errorf("expected 10m expiration from defaults, got %v", resp.CertParams.Expiration)
	}

	// "app" user is not in defaults.Allow, so should fail
	_, err = eval.Evaluate("alice@example.com", policy.Connection{
		RemoteHost: "server1",
		RemoteUser: "app",
	})
	if err == nil {
		t.Error("server1 as app should fail (not in defaults.Allow), got nil")
	}
}

// TestHostPolicyMergesWithDefaults verifies that a host policy's Allow
// is merged with defaults.Allow.
func TestHostPolicyMergesWithDefaults(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"alice@example.com": {"dba", "admin"},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"root": {"admin"}, // admin tag can be root everywhere
			},
		},
		Hosts: map[string]*policyserver.HostPolicy{
			"prod-db-*": {
				Allow: map[string][]string{
					"postgres": {"dba"}, // dba tag can be postgres on prod-db-*
				},
			},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// Should be able to connect as postgres (from host policy)
	_, err := eval.Evaluate("alice@example.com", policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "postgres",
	})
	if err != nil {
		t.Errorf("postgres should be allowed via host policy, got error: %v", err)
	}

	// Should also be able to connect as root (from defaults merged in)
	_, err = eval.Evaluate("alice@example.com", policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "root",
	})
	if err != nil {
		t.Errorf("root should be allowed via merged defaults, got error: %v", err)
	}

	// Check that hostUsers contains both principals
	resp, err := eval.Evaluate("alice@example.com", policy.Connection{})
	if err != nil {
		t.Fatalf("Hello request failed: %v", err)
	}

	users := resp.Policy.HostUsers["prod-db-*"]
	if len(users) != 2 {
		t.Errorf("expected 2 users in hostUsers[prod-db-*], got %d: %v", len(users), users)
	}
}

// TestOnlyDefaultsNoHosts verifies that having only defaults (no hosts) rejects all requests.
func TestOnlyDefaultsNoHosts(t *testing.T) {
	cfg := &policyserver.PolicyRulesConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"root": {"admin"},
			},
		},
		// No Hosts configured
	}

	eval := evaluator.NewForTesting(cfg)

	// Hello request should fail - no host patterns exist
	_, err := eval.Evaluate("alice@example.com", policy.Connection{})
	if err == nil {
		t.Error("Hello request should fail with no hosts configured, got nil")
	}

	// Cert request should also fail
	_, err = eval.Evaluate("alice@example.com", policy.Connection{
		RemoteHost: "any-server",
		RemoteUser: "root",
	})
	if err == nil {
		t.Error("Cert request should fail with no hosts configured, got nil")
	}
}

// Example showing how the evaluator would be used
func ExampleEvaluator() {
	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.DefaultPolicy{
			Allow: map[string][]string{
				"alice": {"admin"},
			},
		},
		// Host patterns are required - defaults.Allow is merged into these
		Hosts: map[string]*policyserver.HostPolicy{
			"*.example.com": {},
		},
	}

	ctx := context.Background()
	eval, _, _ := evaluator.New(ctx, cfg, tlsconfig.Config{})

	// Evaluate would be called with a real OIDC token
	conn := policy.Connection{
		RemoteHost: "server.example.com",
		RemoteUser: "alice",
		Port:       22,
	}

	_, _ = eval.Evaluate("oidc-token-from-auth-command", conn)
}
