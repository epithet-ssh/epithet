package evaluator_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

// mockOIDCServer returns a test server that serves the two endpoints
// coreos/go-oidc needs for provider discovery: openid-configuration
// and an empty JWKS.
func mockOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()
	var url string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"authorization_endpoint":%q,"token_endpoint":%q,"response_types_supported":["code"]}`,
				url, url+"/jwks", url+"/auth", url+"/token")
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	url = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func TestEvaluateGlobalPolicy_UserInList(t *testing.T) {
	mock := mockOIDCServer(t)

	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   mock.URL,
			ClientID: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
			"bob@example.com":   {"user"},
		},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{
				"root": {"admin"},
				"app":  {"user"},
			},
		},
	}

	ctx := context.Background()
	eval, _, err := evaluator.New(ctx, cfg.ExtractServerConfig(), cfg.ExtractPolicyConfig(), tlsconfig.Config{})
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	_ = eval
}

func TestEvaluateGlobalPolicy_DefaultAllow(t *testing.T) {
	mock := mockOIDCServer(t)

	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   mock.URL,
			ClientID: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{
				"root":  {"admin"},
				"guest": {"visitor"},
			},
			Expiration: "5m",
		},
	}

	ctx := context.Background()
	eval, _, err := evaluator.New(ctx, cfg.ExtractServerConfig(), cfg.ExtractPolicyConfig(), tlsconfig.Config{})
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	_ = eval
}

func TestEvaluateHostPolicy(t *testing.T) {
	mock := mockOIDCServer(t)

	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   mock.URL,
			ClientID: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"dba"},
		},
		Hosts: map[string]*policyserver.Rules{
			"prod-db-01": {
				Allow: map[string][]string{
					"postgres": {"dba"},
				},
				Expiration: "2m",
			},
		},
	}

	ctx := context.Background()
	eval, _, err := evaluator.New(ctx, cfg.ExtractServerConfig(), cfg.ExtractPolicyConfig(), tlsconfig.Config{})
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
			ClientID: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := evaluator.New(ctx, cfg.ExtractServerConfig(), cfg.ExtractPolicyConfig(), tlsconfig.Config{})
	if err == nil {
		t.Fatal("expected error for invalid OIDC issuer, got nil")
	}
}

// Unit tests using NewForTesting (no OIDC validation required)

// TestEmptyConnection_NoDefaults_IsForbidden verifies that an empty connection
// (formerly treated as a "Hello request" that succeeded if the user had access
// to anything) is now simply Forbidden - no pattern matches an empty
// RemoteHost, so evaluateHosts finds no authorized match. Hello requests are
// removed entirely in a later task; this only confirms Evaluate no longer
// special-cases them.
func TestEmptyConnection_NoDefaults_IsForbidden(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"dba"},
		},
		// No Defaults - only host-specific rules.
		Hosts: map[string]*policyserver.Rules{
			"prod-db-*": {
				Allow: map[string][]string{
					"postgres": {"dba"},
				},
				Expiration: "2m",
			},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// An empty connection matches no host pattern, so it is Forbidden.
	_, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{})
	if err == nil {
		t.Fatal("expected empty connection to be forbidden, got nil error")
	}

	// A real, matching connection still succeeds, and the cert carries only
	// the requested principal.
	resp, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "postgres",
	})
	if err != nil {
		t.Fatalf("matching connection should succeed, got error: %v", err)
	}
	if len(resp.CertParams.Names) != 1 || resp.CertParams.Names[0] != "postgres" {
		t.Errorf("expected cert principal [postgres], got %v", resp.CertParams.Names)
	}
}

// TestEmptyConnection_WithDefaults_IsForbidden verifies that an empty
// connection is Forbidden even when defaults are merged into a wildcard host
// pattern - an empty RemoteHost still fails doublestar.Match("*", "").
// Note: an explicit host pattern is required - defaults.Allow alone does NOT
// create a wildcard pattern. To match all hosts, add "*": {} to Hosts.
func TestEmptyConnection_WithDefaults_IsForbidden(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{
				"root": {"admin"},
			},
			Expiration: "5m",
		},
		// Explicit wildcard pattern - defaults.Allow is merged into this.
		Hosts: map[string]*policyserver.Rules{
			"*": {},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	_, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{})
	if err == nil {
		t.Fatal("expected empty connection to be forbidden, got nil error")
	}

	// A real, matching connection still succeeds, and the cert carries only
	// the requested principal.
	resp, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "anyhost",
		RemoteUser: "root",
	})
	if err != nil {
		t.Fatalf("matching connection should succeed, got error: %v", err)
	}
	if len(resp.CertParams.Names) != 1 || resp.CertParams.Names[0] != "root" {
		t.Errorf("expected cert principal [root], got %v", resp.CertParams.Names)
	}
}

// TestCertRequest_AuthorizationEnforced verifies regular cert requests still check authorization
func TestCertRequest_AuthorizationEnforced(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"dba"},
		},
		Hosts: map[string]*policyserver.Rules{
			"prod-db-*": {
				Allow: map[string][]string{
					"postgres": {"dba"},
				},
			},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// Authorized request should succeed
	_, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "postgres",
	})
	if err != nil {
		t.Errorf("authorized request should succeed, got error: %v", err)
	}

	// Unauthorized host should fail
	_, err = eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "web-server-01",
		RemoteUser: "postgres",
	})
	if err == nil {
		t.Error("unauthorized host should fail, got nil error")
	}

	// Unauthorized user should fail
	_, err = eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "root",
	})
	if err == nil {
		t.Error("unauthorized user should fail, got nil error")
	}
}

// TestEvaluate_UnknownUser verifies unknown users are rejected
func TestEvaluate_UnknownUser(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// Unknown user should fail (checked before any host matching happens).
	_, err := eval.Evaluate(context.Background(), "unknown@example.com", time.Time{}, policy.Connection{})
	if err == nil {
		t.Error("unknown user should fail, got nil error")
	}
}

// TestEmptyConnection_UserWithNoAccess_IsForbidden verifies that a user who
// exists but has no authorized hosts (their tag grants nothing) is rejected.
func TestEmptyConnection_UserWithNoAccess_IsForbidden(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"guest"}, // Has 'guest' tag but no policies allow 'guest'
		},
		Hosts: map[string]*policyserver.Rules{
			"prod-db-*": {
				Allow: map[string][]string{
					"postgres": {"dba"}, // Only 'dba' tag is allowed
				},
			},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// User exists but has no authorized hosts (their tag doesn't grant access)
	_, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{})
	if err == nil {
		t.Error("user with no authorized hosts should fail, got nil error")
	}
}

// TestHostMustMatchPattern_RejectsUnmatchedHost verifies that hosts not matching
// any pattern in Hosts are rejected, even if defaults.Allow would permit them.
func TestHostMustMatchPattern_RejectsUnmatchedHost(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"brianm@skife.org": {"wheel"},
		},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{
				"brianm": {"wheel"},
			},
			Expiration: "5m",
		},
		Hosts: map[string]*policyserver.Rules{
			"v*":   {Allow: map[string][]string{"brianm": {"wheel"}, "arch": {"wheel"}}},
			"badb": {},
			"hati": {},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// "wobble" doesn't match any pattern in Hosts - should be rejected
	_, err := eval.Evaluate(context.Background(), "brianm@skife.org", time.Time{}, policy.Connection{
		RemoteHost: "wobble",
		RemoteUser: "brianm",
	})
	if err == nil {
		t.Error("expected error for host not matching any pattern, got nil")
	}

	// "v1" matches "v*" - should succeed
	_, err = eval.Evaluate(context.Background(), "brianm@skife.org", time.Time{}, policy.Connection{
		RemoteHost: "v1",
		RemoteUser: "brianm",
	})
	if err != nil {
		t.Errorf("v1 should match v* pattern, got error: %v", err)
	}

	// "badb" matches exactly - should succeed
	_, err = eval.Evaluate(context.Background(), "brianm@skife.org", time.Time{}, policy.Connection{
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
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{
				"root": {"admin"},
			},
			Expiration: "10m",
		},
		Hosts: map[string]*policyserver.Rules{
			"server1": {}, // Empty - should use defaults.Allow
			"server2": {}, // Empty - should use defaults.Allow
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// server1 with empty Allow should get "root" from defaults
	resp, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
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
	_, err = eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
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
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"dba", "admin"},
		},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{
				"root": {"admin"}, // admin tag can be root everywhere
			},
		},
		Hosts: map[string]*policyserver.Rules{
			"prod-db-*": {
				Allow: map[string][]string{
					"postgres": {"dba"}, // dba tag can be postgres on prod-db-*
				},
			},
		},
	}

	eval := evaluator.NewForTesting(cfg)

	// Should be able to connect as postgres (from host policy)
	_, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "postgres",
	})
	if err != nil {
		t.Errorf("postgres should be allowed via host policy, got error: %v", err)
	}

	// Should also be able to connect as root (from defaults merged in)
	_, err = eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "root",
	})
	if err != nil {
		t.Errorf("root should be allowed via merged defaults, got error: %v", err)
	}

	// The cert carries only the requested principal, not the union of
	// everything the user could ask for on this host pattern. Uses a real,
	// matching connection - an empty connection is Forbidden (no pattern
	// matches "").
	resp, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "prod-db-01",
		RemoteUser: "postgres",
	})
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	require.Equal(t, []string{"postgres"}, resp.CertParams.Names)
}

// TestOnlyDefaultsNoHosts verifies that having only defaults (no hosts) rejects all requests.
func TestOnlyDefaultsNoHosts(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{
				"root": {"admin"},
			},
		},
		// No Hosts configured
	}

	eval := evaluator.NewForTesting(cfg)

	// Empty connection should fail - no host patterns exist.
	_, err := eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{})
	if err == nil {
		t.Error("empty connection should fail with no hosts configured, got nil")
	}

	// Cert request should also fail
	_, err = eval.Evaluate(context.Background(), "alice@example.com", time.Time{}, policy.Connection{
		RemoteHost: "any-server",
		RemoteUser: "root",
	})
	if err == nil {
		t.Error("Cert request should fail with no hosts configured, got nil")
	}
}

// evaluatorForConfig is a thin wrapper around NewForTesting, kept as a named
// helper so call sites read as "build an evaluator for this policy config".
func evaluatorForConfig(cfg *policyserver.PolicyConfig) *evaluator.Evaluator {
	return evaluator.NewForTesting(cfg)
}

// TestHostRuleSelectionIsDeterministic verifies that when multiple host
// patterns match a connection, the same (most specific) pattern wins every
// time - regardless of Go's randomized map iteration order. Before this was
// fixed, "*.example.com" and "prod-*.example.com" could each win depending on
// map order, so the resulting cert expiration was flaky.
func TestHostRuleSelectionIsDeterministic(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{"alice@example.com": {"admin"}},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{"root": {"admin"}}, Expiration: "30m",
		},
		Hosts: map[string]*policyserver.Rules{
			"*.example.com":      {Expiration: "30m"},
			"prod-*.example.com": {Expiration: "2m"},
		},
	}
	e := evaluatorForConfig(cfg)
	conn := policy.Connection{RemoteHost: "prod-db.example.com", RemoteUser: "root"}

	// Run many times: map iteration order must not leak into the result.
	for range 50 {
		resp, err := e.Evaluate(context.Background(), "alice@example.com", time.Time{}, conn)
		require.NoError(t, err)
		require.Equal(t, 2*time.Minute, resp.CertParams.Expiration,
			"longest (most specific) pattern must always win")
	}
}

// TestCertCarriesOnlyRequestedPrincipal verifies that the certificate names
// only the principal actually requested for this connection - not the union
// of every principal the user's tags could reach anywhere in the policy (see
// Task 11b: authorization maps leave the wire entirely, and certs become
// strictly per-connection).
func TestCertCarriesOnlyRequestedPrincipal(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{"alice@example.com": {"admin"}},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{"root": {"admin"}, "deploy": {"admin"}},
		},
		Hosts: map[string]*policyserver.Rules{"*.example.com": {}},
	}
	e := evaluator.NewForTesting(cfg)
	resp, err := e.Evaluate(context.Background(), "alice@example.com",
		time.Now().Add(5*time.Minute),
		policy.Connection{RemoteHost: "web.example.com", RemoteUser: "root"})
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, resp.CertParams.Names,
		"cert must not carry the union of all authorized principals")
}

// TestEvaluateSetsNotAfterFromTokenExpiry verifies that the tokenExpiry
// passed into Evaluate flows through unchanged into CertParams.NotAfter, so
// the CA can later clamp the issued certificate to the auth session's
// remaining lifetime.
func TestEvaluateSetsNotAfterFromTokenExpiry(t *testing.T) {
	cfg := &policyserver.PolicyConfig{
		Users: map[string][]string{"alice@example.com": {"admin"}},
		Hosts: map[string]*policyserver.Rules{
			"web.example.com": {Allow: map[string][]string{"root": {"admin"}}},
		},
	}
	e := evaluatorForConfig(cfg)
	exp := time.Now().Add(3 * time.Minute)

	resp, err := e.Evaluate(context.Background(), "alice@example.com", exp,
		policy.Connection{RemoteHost: "web.example.com", RemoteUser: "root"})
	require.NoError(t, err)
	require.Equal(t, exp, resp.CertParams.NotAfter)
}

// Example showing how the evaluator would be used
func ExampleEvaluator() {
	cfg := &policyserver.PolicyRulesConfig{
		CAPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE...",
		OIDC: policyserver.OIDCConfig{
			Issuer:   "https://accounts.google.com",
			ClientID: "test-client-id",
		},
		Users: map[string][]string{
			"alice@example.com": {"admin"},
		},
		Defaults: &policyserver.Rules{
			Allow: map[string][]string{
				"alice": {"admin"},
			},
		},
		// Host patterns are required - defaults.Allow is merged into these
		Hosts: map[string]*policyserver.Rules{
			"*.example.com": {},
		},
	}

	ctx := context.Background()
	eval, _, _ := evaluator.New(ctx, cfg.ExtractServerConfig(), cfg.ExtractPolicyConfig(), tlsconfig.Config{})

	// Evaluate would be called with a real OIDC token
	conn := policy.Connection{
		RemoteHost: "server.example.com",
		RemoteUser: "alice",
		Port:       22,
	}

	_, _ = eval.Evaluate(ctx, "oidc-token-from-auth-command", time.Time{}, conn)
}
