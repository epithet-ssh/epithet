package policy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/inventory"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/policyserver/writpolicy"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/stretchr/testify/require"
)

// newIntegrationHandler builds the real policy HTTP handler the same way the
// `epithet policy` command does: write a .writ policy file and a static
// inventory file, compile them with writ.Load + inventory.NewStatic, build
// the real writpolicy evaluator + OIDC validator (which performs real HTTP
// discovery against idp, exercising the actual token-validation path end to
// end), and wire policyserver.NewHandler. Returns the handler, the IdP used
// to mint tokens, and a sign func that service-signs requests exactly like
// the real CA does (Config.CAPublicKey requires every request be signed).
func newIntegrationHandler(t *testing.T) (http.Handler, *oidctest.IdP, func(*http.Request, []byte)) {
	t.Helper()

	idp := oidctest.New(t)

	caPub, caPriv, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.writ")
	require.NoError(t, os.WriteFile(policyPath,
		[]byte("allow id:\"alice@example.com\" -> root@*\n"), 0644))
	invPath := filepath.Join(tmpDir, "inventory.yaml")
	require.NoError(t, os.WriteFile(invPath,
		[]byte("users:\n  - userName: alice@example.com\nhosts:\n  - pattern: \"*\"\n"), 0644))

	src, err := os.ReadFile(policyPath)
	require.NoError(t, err)
	pol, diags := writ.Load(string(src))
	require.NotNil(t, pol, "policy failed to load: %v", diags)

	inv, err := inventory.NewStatic([]string{invPath})
	require.NoError(t, err)

	// The default TTL stays at the deployment default (5m), deliberately
	// distinct from the 2m token minted below so the NotAfter assertion
	// discriminates (see TestPolicyIntegration_ValidToken_ReturnsCertParams).
	eval, warnings, err := writpolicy.New(pol, inv, &writpolicy.Registry{}, writpolicy.Options{})
	require.NoError(t, err)
	require.Empty(t, warnings)

	// oidc.NewValidator performs real OIDC discovery against idp - the
	// same construction path `epithet policy` uses, not a stub validator.
	validator, err := oidc.NewValidator(context.Background(), oidc.Config{
		Issuer:    idp.Issuer(),
		ClientID:  oidctest.ClientID,
		TLSConfig: tlsconfig.Config{},
	})
	require.NoError(t, err)

	handler, err := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: caPub,
		Validator:   validator,
		Evaluator:   eval,
		Discovery: &wire.Discovery{Auth: &wire.AuthConfig{
			Issuer:   idp.Issuer(),
			ClientID: oidctest.ClientID,
		}},
	})
	require.NoError(t, err)

	signer, err := serviceauth.NewSigner(caPriv)
	require.NoError(t, err)
	sign := func(req *http.Request, body []byte) {
		require.NoError(t, signer.Authorize(req, body))
	}

	return handler, idp, sign
}

// doPolicyRequest POSTs a service-signed cert evaluation request and returns
// the recorded response.
func doPolicyRequest(t *testing.T, handler http.Handler, sign func(*http.Request, []byte), token string, conn policy.Connection) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(wire.PolicyRequest{Token: token, Connection: conn})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	sign(req, body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// TestPolicyIntegration_ValidToken_ReturnsCertParams exercises the full real
// path (real JWT signed by a real IdP, real discovery/JWKS fetch, real
// evaluator) end to end: a valid token for an authorized user/host/principal
// combination gets a 200 with cert params clamped to the token's own expiry
// and naming exactly the requested principal - never a union of everything
// the user's tags could reach.
//
// The token is minted with a 2m lifetime, deliberately distinct from the
// policy's own "defaults.expiration: 5m" (see newIntegrationHandler): if
// NotAfter were ever computed from the policy's expiration duration instead
// of the token's actual exp claim, both would land on ~5m and this
// assertion would pass either way. A mismatched pair makes the WithinDuration
// check below actually discriminate between the two.
func TestPolicyIntegration_ValidToken_ReturnsCertParams(t *testing.T) {
	handler, idp, sign := newIntegrationHandler(t)

	exp := time.Now().Add(2 * time.Minute).Truncate(time.Second)
	token := idp.MintIDToken("alice@example.com", exp)

	w := doPolicyRequest(t, handler, sign, token, policy.Connection{
		RemoteHost: "prod.example.com",
		RemoteUser: "root",
		Port:       22,
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp wire.PolicyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, []string{"root"}, resp.CertParams.Names)
	require.WithinDuration(t, exp, resp.CertParams.NotAfter, time.Second,
		"cert NotAfter must be clamped to the token's own expiry")
}

// TestPolicyIntegration_ExpiredToken_Returns401 verifies real expiry
// enforcement: the token's exp claim is in the past, so the real OIDC
// verifier must reject it before the evaluator ever runs.
func TestPolicyIntegration_ExpiredToken_Returns401(t *testing.T) {
	handler, idp, sign := newIntegrationHandler(t)

	token := idp.MintIDToken("alice@example.com", time.Now().Add(-time.Minute))

	w := doPolicyRequest(t, handler, sign, token, policy.Connection{
		RemoteHost: "prod.example.com",
		RemoteUser: "root",
	})
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

// TestPolicyIntegration_WrongAudience_Returns401 verifies the validator
// enforces the configured client_id as audience: a token signed by the same
// IdP but for a different client must be rejected.
func TestPolicyIntegration_WrongAudience_Returns401(t *testing.T) {
	handler, idp, sign := newIntegrationHandler(t)

	token := idp.MintIDTokenWithAudience("alice@example.com", "someone-elses-client", time.Now().Add(time.Minute))

	w := doPolicyRequest(t, handler, sign, token, policy.Connection{
		RemoteHost: "prod.example.com",
		RemoteUser: "root",
	})
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

// TestPolicyIntegration_UnknownUser_Returns403 verifies a validly signed
// token for an identity absent from the policy's users list is authenticated
// fine but denied by authorization - a 403, not a 401.
func TestPolicyIntegration_UnknownUser_Returns403(t *testing.T) {
	handler, idp, sign := newIntegrationHandler(t)

	token := idp.MintIDToken("mallory@example.com", time.Now().Add(time.Minute))

	w := doPolicyRequest(t, handler, sign, token, policy.Connection{
		RemoteHost: "prod.example.com",
		RemoteUser: "root",
	})
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
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
		"--oidc-issuer",
		"--oidc-client-id",
		"--ca-pubkey",
		"--listen",
		"--policy-file",
		"--inventory",
		"--check",
		"OIDC-based authorization",
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
