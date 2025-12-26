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

// TestHelloRequest_WithDefaults verifies Hello requests work with defaults too
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
		t.Error("expected '*' pattern in hostUsers from defaults")
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
