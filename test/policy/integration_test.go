package policy_test

import (
	"bytes"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/internal/inventorytest"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/writpolicy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/stretchr/testify/require"
)

// newIntegrationHandler wires real inventory authentication, policy evaluation, and CA coordination.
func newIntegrationHandler(t *testing.T) (*ca.CA, *oidctest.IdP) {
	t.Helper()

	idp := oidctest.New(t)

	caPub, caPriv, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.writ")
	require.NoError(t, os.WriteFile(policyPath,
		[]byte("allow userName:\"alice@example.com\" -> root@*\n"), 0644))
	invPath := filepath.Join(tmpDir, "inventory.yaml")
	require.NoError(t, os.WriteFile(invPath,
		[]byte("users:\n  - userName: alice@example.com\n    id: subject:alice@example.com\nhosts:\n  - pattern: \"*\"\n"), 0644))

	src, err := os.ReadFile(policyPath)
	require.NoError(t, err)
	pol, diags := writ.Load(string(src))
	require.NotNil(t, pol, "policy failed to load: %v", diags)

	inv, err := inventory.NewStatic([]string{invPath})
	require.NoError(t, err)

	// The default TTL stays at the deployment default (5m), deliberately
	// distinct from the 2m token minted below so the CA expiry assertion
	// discriminates (see TestPolicyIntegration_ValidToken_ReturnsSigningInputs).
	eval, warnings, err := writpolicy.New(pol, &writpolicy.Registry{}, writpolicy.Options{})
	require.NoError(t, err)
	require.Empty(t, warnings)

	handler, err := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: caPub,
		Evaluator:   eval,
	})
	require.NoError(t, err)

	ps := httptest.NewServer(handler)
	t.Cleanup(ps.Close)
	is := inventorytest.Serve(t, inv, idp.Issuer(), caPub)
	authority, err := ca.New(caPriv, ps.URL, ca.WithInventory(is.URL, tlsconfig.Config{Insecure: true}))
	require.NoError(t, err)
	return authority, idp
}

// TestPolicyIntegration_ValidToken_ReturnsSigningInputs exercises inventory OIDC
// validation, policy evaluation, and CA construction together. The CA derives
// the requested principal and enforces the token expiry independently of TTL.
func TestPolicyIntegration_ValidToken_ReturnsSigningInputs(t *testing.T) {
	handler, idp := newIntegrationHandler(t)

	exp := time.Now().Add(2 * time.Minute).Truncate(time.Second)
	token := idp.MintIDToken("alice@example.com", exp)

	resp, err := handler.RequestPolicy(t.Context(), token, policy.Connection{
		RemoteHost: "prod.example.com",
		RemoteUser: "root",
		Port:       22,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, resp.CertParams.Names)
	require.Equal(t, "alice@example.com", resp.CertParams.Identity)
	require.Equal(t, 5*time.Minute, resp.CertParams.Expiration)
	require.WithinDuration(t, exp, resp.CertParams.NotAfter, 0)
}

// TestPolicyIntegration_ExpiredToken_ReturnsAuthenticationError verifies real expiry
// enforcement: the token's exp claim is in the past, so the real OIDC
// verifier must reject it before the evaluator ever runs.
func TestPolicyIntegration_ExpiredToken_ReturnsAuthenticationError(t *testing.T) {
	handler, idp := newIntegrationHandler(t)

	token := idp.MintIDToken("alice@example.com", time.Now().Add(-time.Minute))

	_, err := handler.RequestPolicy(t.Context(), token, policy.Connection{
		RemoteHost: "prod.example.com",
		RemoteUser: "root",
	})
	require.ErrorIs(t, err, ca.ErrInvalidAuthentication)
}

// TestPolicyIntegration_WrongAudience_ReturnsAuthenticationError verifies the validator
// enforces the configured client_id as audience: a token signed by the same
// IdP but for a different client must be rejected.
func TestPolicyIntegration_WrongAudience_ReturnsAuthenticationError(t *testing.T) {
	handler, idp := newIntegrationHandler(t)

	token := idp.MintIDTokenWithAudience("alice@example.com", "someone-elses-client", time.Now().Add(time.Minute))

	_, err := handler.RequestPolicy(t.Context(), token, policy.Connection{
		RemoteHost: "prod.example.com",
		RemoteUser: "root",
	})
	require.ErrorIs(t, err, ca.ErrInvalidAuthentication)
}

// TestPolicyIntegration_UnknownUser_ReturnsDenial verifies a validly signed
// token for an identity absent from the policy's users list is authenticated
// fine but denied by authorization - a 403, not a 401.
func TestPolicyIntegration_UnknownUser_ReturnsDenial(t *testing.T) {
	handler, idp := newIntegrationHandler(t)

	token := idp.MintIDToken("mallory@example.com", time.Now().Add(time.Minute))

	_, err := handler.RequestPolicy(t.Context(), token, policy.Connection{
		RemoteHost: "prod.example.com",
		RemoteUser: "root",
	})
	require.ErrorIs(t, err, ca.ErrAccessDenied)
}

// TestPolicyServerCommand validates that the policy command exists and shows help
func TestPolicyServerCommand(t *testing.T) {
	tempDir := t.TempDir()
	epithetBin := filepath.Join(tempDir, "epithet")

	// Build the epithet binary
	buildCmd := exec.Command("go", "build", "-o", epithetBin, "../../cmd/epithet")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build epithet: %v\n%s", err, output)
	}

	// Test that 'epithet policy --help' works
	cmd := exec.Command(epithetBin, "policy", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run epithet policy --help: %v\n%s", err, output)
	}

	outputStr := string(output)

	// Verify help output contains expected flags
	expectedStrings := []string{
		"--ca-pubkey",
		"--listen",
		"--policy-file",
		"--check",
		"normalized facts",
	}

	for _, expected := range expectedStrings {
		if !contains(outputStr, expected) {
			t.Errorf("help output missing %q\nOutput:\n%s", expected, outputStr)
		}
	}
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
