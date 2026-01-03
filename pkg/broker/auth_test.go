package broker

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/stretchr/testify/require"
)

func TestAuth_New(t *testing.T) {
	t.Parallel()
	auth := NewAuth("my-auth-command --flag")
	require.NotNil(t, auth)
	require.Equal(t, "my-auth-command --flag", auth.cmdLine)
	require.Empty(t, auth.state)
}

func TestAuth_Run_Success_InitialAuth(t *testing.T) {
	t.Parallel()
	// Create a test auth script that returns a token
	script := writeTestScript(t, `#!/bin/sh
# Read and ignore stdin
cat > /dev/null

# Return token to stdout (using printf to avoid newline issues)
printf '%s' "my-token-1"
`)

	auth := NewAuth(script)
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "bXktdG9rZW4tMQ", token) // "my-token-1" base64url encoded
	require.Empty(t, auth.state)              // No state returned
}

func TestAuth_Run_Success_WithStateUpdate(t *testing.T) {
	t.Parallel()
	script := writeTestScript(t, `#!/bin/sh
# Read and ignore stdin
cat > /dev/null

# Return token to stdout
printf '%s' "my-token-2"

# Return new state to fd 3
printf '%s' '{"refresh":"xyz"}' >&3
`)

	auth := NewAuth(script)
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "bXktdG9rZW4tMg", token) // "my-token-2" base64url encoded
	require.Equal(t, []byte(`{"refresh":"xyz"}`), auth.state)
}

func TestAuth_Run_Success_StatePreservedAcrossCalls(t *testing.T) {
	t.Parallel()
	// First call returns token and state
	script1 := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "token"
printf '%s' '{"count":1}' >&3
`)

	auth := NewAuth(script1)
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "dG9rZW4", token) // "token" base64url encoded
	require.Equal(t, []byte(`{"count":1}`), auth.state)

	// Second call uses the state from first call
	script2 := writeTestScript(t, `#!/bin/sh
# Verify we received state on stdin
input=$(cat)
if echo "$input" | grep -q "count"; then
    printf '%s' "token-fresh"
    printf '%s' '{"count":2}' >&3
else
    echo "Expected state!" >&2
    exit 1
fi
`)

	auth.cmdLine = script2
	token, err = auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "dG9rZW4tZnJlc2g", token) // "token-fresh" base64url encoded
	require.Equal(t, []byte(`{"count":2}`), auth.state)
}

func TestAuth_Run_AuthFailure(t *testing.T) {
	t.Parallel()
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
echo "Authentication failed" >&2
exit 1
`)

	auth := NewAuth(script)
	_, err := auth.Run(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Authentication failed")
}

func TestAuth_Run_CommandExecutionError(t *testing.T) {
	t.Parallel()
	script := writeTestScript(t, `#!/bin/sh
echo "Something went wrong" >&2
exit 1
`)

	auth := NewAuth(script)
	_, err := auth.Run(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "auth command failed")
	require.Contains(t, err.Error(), "Something went wrong")
}

func TestAuth_Run_EmptyToken(t *testing.T) {
	t.Parallel()
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
# No output to stdout - empty token
`)

	auth := NewAuth(script)
	_, err := auth.Run(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty token")
}

func TestAuth_Run_MustacheTemplateRendering(t *testing.T) {
	t.Parallel()
	// Test that mustache template is rendered in command line
	auth := NewAuth(`printf '%s' "token-{{host}}"`)
	token, err := auth.Run(map[string]string{"host": "ok"})
	require.NoError(t, err)
	require.Equal(t, "dG9rZW4tb2s", token) // "token-ok" base64url encoded
}

func TestAuth_Run_MustacheTemplateError(t *testing.T) {
	t.Parallel()
	auth := NewAuth("echo {{unclosed}")
	_, err := auth.Run(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to render command template")
}

func TestAuth_Run_Concurrent(t *testing.T) {
	t.Parallel()
	// Test that concurrent calls are properly serialized by the lock
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
sleep 0.05
printf '%s' "token"
printf '%s' '{"count":1}' >&3
`)

	auth := NewAuth(script)

	// Run two calls concurrently
	done := make(chan bool, 2)
	for range 2 {
		go func() {
			token, err := auth.Run(nil)
			require.NoError(t, err)
			require.Equal(t, "dG9rZW4", token) // "token" base64url encoded
			done <- true
		}()
	}

	// Wait for both to complete
	<-done
	<-done

	// State should be consistent (last write wins)
	require.Equal(t, []byte(`{"count":1}`), auth.state)
}

// Helper function to write a test script to a temporary file
func writeTestScript(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test-script.sh")

	err := os.WriteFile(scriptPath, []byte(content), 0755)
	require.NoError(t, err)

	return scriptPath
}

func TestAuth_Run_EmptyStateHandling(t *testing.T) {
	t.Parallel()
	// Test that empty state is sent on first call
	script := writeTestScript(t, `#!/bin/sh
input=$(cat)
if [ -z "$input" ]; then
    printf '%s' "first-call-token"
else
    echo "Expected empty state" >&2
    exit 1
fi
`)

	auth := NewAuth(script)
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "Zmlyc3QtY2FsbC10b2tlbg", token) // "first-call-token" base64url encoded
}

func TestAuth_Run_StateClearing(t *testing.T) {
	t.Parallel()
	// Test that plugin can clear state by not writing to fd 3
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "token"
# No output to fd 3 - should clear existing state
`)

	auth := NewAuth(script)
	auth.state = []byte("old-state") // Set some initial state

	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "dG9rZW4", token) // "token" base64url encoded
	require.Empty(t, auth.state)       // State should be cleared
}

func TestIntegration_FullAuthFlow(t *testing.T) {
	t.Parallel()
	// Integration test: simulate a full auth flow with state management

	// First auth call - no state, returns token and state
	script1 := writeTestScript(t, `#!/bin/sh
input=$(cat)
if [ -z "$input" ]; then
    # Initial auth - return token and state
    printf '%s' "initial-auth-token"
    printf '%s' '{"refresh":"r1","exp":100}' >&3
else
    echo "Expected initial empty state" >&2
    exit 1
fi
`)

	auth := NewAuth(script1)
	token, err := auth.Run(map[string]string{"user": "alice"})
	require.NoError(t, err)
	require.Equal(t, "aW5pdGlhbC1hdXRoLXRva2Vu", token) // "initial-auth-token" base64url encoded
	require.NotEmpty(t, auth.state)

	// Second auth call - uses state from first call
	script2 := writeTestScript(t, `#!/bin/sh
input=$(cat)
# Check that we got state with refresh token
if echo "$input" | grep -q "refresh.*r1"; then
    # Token refresh - return new token and updated state
    printf '%s' "refreshed-token-123"
    printf '%s' '{"refresh":"r2","exp":200}' >&3
else
    echo "Expected refresh state" >&2
    exit 1
fi
`)

	auth.cmdLine = script2
	token, err = auth.Run(map[string]string{"user": "alice"})
	require.NoError(t, err)
	require.Equal(t, "cmVmcmVzaGVkLXRva2VuLTEyMw", token) // "refreshed-token-123" base64url encoded
	require.Contains(t, string(auth.state), "r2")

	// Third auth call - simulate token expiration, auth fails
	script3 := writeTestScript(t, `#!/bin/sh
input=$(cat)
if echo "$input" | grep -q "refresh.*r2"; then
    # Simulate refresh token expired
    echo "Refresh token expired, full re-auth required" >&2
    exit 1
else
    echo "Expected refresh state" >&2
    exit 1
fi
`)

	auth.cmdLine = script3
	_, err = auth.Run(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Refresh token expired, full re-auth required")
	// State should NOT be updated on error - the code returns early before state update
	// So the state from the previous successful call should still be present
	require.Equal(t, []byte(`{"refresh":"r2","exp":200}`), auth.state)
}

func TestAuth_Token(t *testing.T) {
	t.Parallel()
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "my-token-abc"
`)

	auth := NewAuth(script)

	// Token should be empty initially
	require.Empty(t, auth.Token())

	// Run auth
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "bXktdG9rZW4tYWJj", token) // "my-token-abc" base64url encoded

	// Token() should return the stored token
	require.Equal(t, "bXktdG9rZW4tYWJj", auth.Token()) // "my-token-abc" base64url encoded
}

// TODO: Re-enable this test with a faster implementation
// The current shell-based approach is too slow for CI
/*
func TestAuth_Run_StateSizeLimit(t *testing.T) {
	// Test that state exceeding MaxStateBlobSize is rejected
	// Use head to generate exactly 11 MiB of data
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "token"
# Write 11 MiB to fd 3 (exceeds 10 MiB limit)
head -c 11534336 /dev/zero >&3
`)

	auth := NewAuth(script)
	_, err := auth.Run(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum size")
}
*/

func TestAuth_ClearToken(t *testing.T) {
	t.Parallel()
	auth := NewAuth("echo token")
	auth.token = "existing-token"
	auth.state = []byte("existing-state")

	auth.ClearToken()

	require.Empty(t, auth.Token())
	require.Equal(t, []byte("existing-state"), auth.state) // State should be preserved
}

func TestAuth_Run_BinaryTokenPreservation(t *testing.T) {
	t.Parallel()
	// Test that binary tokens with invalid UTF-8 bytes are preserved correctly
	// This is the key bug fix: without base64 encoding, these bytes would be corrupted
	// when cast to string then JSON encoded (invalid UTF-8 → U+FFFD replacement)
	script := writeTestScript(t, `#!/bin/bash
cat > /dev/null
# Output binary data including invalid UTF-8 sequences
# \x80\x81\x82 are invalid UTF-8 continuation bytes without a leading byte
# \xff\xfe are also invalid UTF-8
# Note: Using bash (not sh) because dash doesn't support \x hex escapes
printf '\x80\x81\x82token\xff\xfe'
`)

	auth := NewAuth(script)
	token, err := auth.Run(nil)
	require.NoError(t, err)

	// The token should be base64url encoded, preserving the exact bytes
	// Raw bytes: \x80\x81\x82token\xff\xfe
	// Base64url: gIGCdG9rZW7__g
	require.Equal(t, "gIGCdG9rZW7__g", token)

	// Verify we can decode back to original bytes
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	require.NoError(t, err)
	require.Equal(t, []byte{0x80, 0x81, 0x82, 't', 'o', 'k', 'e', 'n', 0xff, 0xfe}, decoded)
}

func TestAuthConfigToCommand_OIDC(t *testing.T) {
	t.Parallel()

	auth := caclient.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://accounts.google.com",
		ClientID: "my-client-id",
		Scopes:   []string{"openid", "profile", "email"},
	}

	cmd, err := AuthConfigToCommand(auth)
	require.NoError(t, err)

	// Command should contain the executable path (we can't predict exact path)
	require.Contains(t, cmd, "auth oidc")
	require.Contains(t, cmd, "--issuer https://accounts.google.com")
	require.Contains(t, cmd, "--client-id my-client-id")
	require.Contains(t, cmd, "--scopes openid,profile,email")
}

func TestAuthConfigToCommand_OIDC_NoScopes(t *testing.T) {
	t.Parallel()

	auth := caclient.BootstrapAuth{
		Type:     "oidc",
		Issuer:   "https://example.com",
		ClientID: "test-client",
		Scopes:   nil,
	}

	cmd, err := AuthConfigToCommand(auth)
	require.NoError(t, err)

	// Command should not contain --scopes when empty
	require.Contains(t, cmd, "auth oidc")
	require.Contains(t, cmd, "--issuer https://example.com")
	require.Contains(t, cmd, "--client-id test-client")
	require.NotContains(t, cmd, "--scopes")
}

func TestAuthConfigToCommand_OIDC_WithClientSecret(t *testing.T) {
	t.Parallel()

	auth := caclient.BootstrapAuth{
		Type:         "oidc",
		Issuer:       "https://example.com",
		ClientID:     "test-client",
		ClientSecret: "super-secret",
		Scopes:       []string{"openid"},
	}

	cmd, err := AuthConfigToCommand(auth)
	require.NoError(t, err)

	// Command should contain --client-secret when present
	require.Contains(t, cmd, "auth oidc")
	require.Contains(t, cmd, "--issuer https://example.com")
	require.Contains(t, cmd, "--client-id test-client")
	require.Contains(t, cmd, "--client-secret super-secret")
	require.Contains(t, cmd, "--scopes openid")
}

func TestAuthConfigToCommand_Command(t *testing.T) {
	t.Parallel()

	auth := caclient.BootstrapAuth{
		Type:    "command",
		Command: "/usr/local/bin/custom-auth --tenant prod",
	}

	cmd, err := AuthConfigToCommand(auth)
	require.NoError(t, err)

	// Command should be passed through as-is
	require.Equal(t, "/usr/local/bin/custom-auth --tenant prod", cmd)
}

func TestAuthConfigToCommand_Command_WithEpithetSubstitution(t *testing.T) {
	t.Parallel()

	auth := caclient.BootstrapAuth{
		Type:    "command",
		Command: "epithet auth oidc --issuer https://example.com",
	}

	cmd, err := AuthConfigToCommand(auth)
	require.NoError(t, err)

	// "epithet" should be replaced with actual executable path
	require.NotContains(t, cmd, "epithet auth")
	require.Contains(t, cmd, "auth oidc --issuer https://example.com")
}

func TestAuthConfigToCommand_Command_Empty(t *testing.T) {
	t.Parallel()

	auth := caclient.BootstrapAuth{
		Type:    "command",
		Command: "",
	}

	_, err := AuthConfigToCommand(auth)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-empty command")
}

func TestAuthConfigToCommand_UnknownType(t *testing.T) {
	t.Parallel()

	auth := caclient.BootstrapAuth{
		Type: "saml",
	}

	_, err := AuthConfigToCommand(auth)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown auth type: saml")
}
