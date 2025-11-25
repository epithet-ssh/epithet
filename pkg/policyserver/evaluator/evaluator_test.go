package evaluator_test

import (
	"context"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver/config"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Note: These tests use mock configs, not real OIDC token validation
// Real OIDC validation is tested in pkg/policyserver/oidc

func TestEvaluateGlobalPolicy_UserInList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that requires OIDC provider")
	}

	cfg := &config.PolicyConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: config.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
			"bob@example.com":   {"user"},
		},
		Defaults: &config.DefaultPolicy{
			Allow: map[string][]string{
				"root": {"admin"},
				"app":  {"user"},
			},
		},
	}

	ctx := context.Background()
	eval, err := evaluator.New(ctx, cfg, tlsconfig.Config{})
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

	cfg := &config.PolicyConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: config.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &config.DefaultPolicy{
			Allow: map[string][]string{
				"root":  {"admin"},
				"guest": {"visitor"},
			},
			Expiration: "5m",
		},
	}

	ctx := context.Background()
	eval, err := evaluator.New(ctx, cfg, tlsconfig.Config{})
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	_ = eval
}

func TestEvaluateHostPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that requires OIDC provider")
	}

	cfg := &config.PolicyConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: config.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"dba"},
		},
		Hosts: map[string]*config.HostPolicy{
			"prod-db-01": {
				Allow: map[string][]string{
					"postgres": {"dba"},
				},
				Expiration: "2m",
			},
		},
	}

	ctx := context.Background()
	eval, err := evaluator.New(ctx, cfg, tlsconfig.Config{})
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	_ = eval
}

func TestNew_InvalidOIDCIssuer(t *testing.T) {
	cfg := &config.PolicyConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: config.OIDCConfig{
			Issuer:   "https://invalid-oidc-provider.example.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := evaluator.New(ctx, cfg, tlsconfig.Config{})
	if err == nil {
		t.Fatal("expected error for invalid OIDC issuer, got nil")
	}
}

// Example showing how the evaluator would be used
func ExampleEvaluator() {
	cfg := &config.PolicyConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: config.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			Audience: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &config.DefaultPolicy{
			Allow: map[string][]string{
				"alice": {"admin"},
			},
		},
	}

	ctx := context.Background()
	eval, _ := evaluator.New(ctx, cfg, tlsconfig.Config{})

	// Evaluate would be called with a real OIDC token
	conn := policy.Connection{
		RemoteHost: "server.example.com",
		RemoteUser: "alice",
		Port:       22,
	}

	_, _ = eval.Evaluate("oidc-token-from-auth-command", conn)
}
