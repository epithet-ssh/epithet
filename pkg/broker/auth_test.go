package broker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/markdingo/netstring"
	"github.com/stretchr/testify/require"
)

// Test that the netstring library rejects whitespace (strict mode)
func Test_NetString_StrictMode(t *testing.T) {
	msg := "6:nBrian, 8:sSailing,"
	dec := netstring.NewDecoder(strings.NewReader(msg))
	k, m, err := dec.DecodeKeyed()
	require.NoError(t, err)
	require.Equal(t, "n", k.String())
	require.Equal(t, "Brian", string(m))

	// Second decode should fail due to space after comma
	k, m, err = dec.DecodeKeyed()
	require.Error(t, err)
}

func TestEncodeAuthInput_EmptyState(t *testing.T) {
	encoded, err := EncodeAuthInput([]byte{})
	require.NoError(t, err)
	require.Equal(t, "0:,", string(encoded))
}

func TestEncodeAuthInput_WithState(t *testing.T) {
	state := []byte(`{"refresh_token":"abc123"}`)
	encoded, err := EncodeAuthInput(state)
	require.NoError(t, err)

	// Verify it's a valid keyed netstring with 's' key
	dec := netstring.NewDecoder(bytes.NewReader(encoded))
	key, value, err := dec.DecodeKeyed()
	require.NoError(t, err)
	require.Equal(t, byte(KeyState), byte(key))
	require.Equal(t, state, value)
}

func TestEncodeAuthInput_NilState(t *testing.T) {
	// nil state should behave like empty state
	encoded, err := EncodeAuthInput(nil)
	require.NoError(t, err)
	require.Equal(t, "0:,", string(encoded))
}

func TestDecodeAuthOutput_TokenOnly(t *testing.T) {
	// Token without state - build with encoder to ensure correct format
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes(KeyToken, []byte("my-token-1")))

	output, err := DecodeAuthOutput(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, "my-token-1", output.Token)
	require.Empty(t, output.State)
	require.Empty(t, output.Error)
}

func TestDecodeAuthOutput_TokenWithState(t *testing.T) {
	// Token with state
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes(KeyToken, []byte("my-token")))
	require.NoError(t, enc.EncodeBytes(KeyState, []byte(`{"refresh":"xyz"}`)))

	output, err := DecodeAuthOutput(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, "my-token", output.Token)
	require.Equal(t, []byte(`{"refresh":"xyz"}`), output.State)
	require.Empty(t, output.Error)
}

func TestDecodeAuthOutput_ErrorOnly(t *testing.T) {
	// Error without state - build with encoder to ensure correct format
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes(KeyError, []byte("Authentication failed, sorry")))

	output, err := DecodeAuthOutput(buf.Bytes())
	require.NoError(t, err)
	require.Empty(t, output.Token)
	require.Empty(t, output.State)
	require.Equal(t, "Authentication failed, sorry", output.Error)
}

func TestDecodeAuthOutput_ErrorWithState(t *testing.T) {
	// Error with state (state preserved on error)
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes(KeyError, []byte("Token expired")))
	require.NoError(t, enc.EncodeBytes(KeyState, []byte(`{"attempts":3}`)))

	output, err := DecodeAuthOutput(buf.Bytes())
	require.NoError(t, err)
	require.Empty(t, output.Token)
	require.Equal(t, []byte(`{"attempts":3}`), output.State)
	require.Equal(t, "Token expired", output.Error)
}

func TestDecodeAuthOutput_UnknownKeysIgnored(t *testing.T) {
	// Unknown keys should be ignored for forward compatibility
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes('x', []byte("unknown")))
	require.NoError(t, enc.EncodeBytes(KeyToken, []byte("my-token")))
	require.NoError(t, enc.EncodeBytes('y', []byte("also unknown")))

	output, err := DecodeAuthOutput(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, "my-token", output.Token)
	require.Empty(t, output.Error)
}

func TestDecodeAuthOutput_EmptyOutput(t *testing.T) {
	_, err := DecodeAuthOutput([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty output")
}

func TestDecodeAuthOutput_InvalidNetstring(t *testing.T) {
	_, err := DecodeAuthOutput([]byte("not a netstring"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid netstring")
}

func TestDecodeAuthOutput_MultipleTokens(t *testing.T) {
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes(KeyToken, []byte("token1")))
	require.NoError(t, enc.EncodeBytes(KeyToken, []byte("token2")))

	_, err := DecodeAuthOutput(buf.Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "multiple token fields")
}

func TestDecodeAuthOutput_MultipleErrors(t *testing.T) {
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes(KeyError, []byte("error1")))
	require.NoError(t, enc.EncodeBytes(KeyError, []byte("error2")))

	_, err := DecodeAuthOutput(buf.Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "multiple error fields")
}

func TestDecodeAuthOutput_BothTokenAndError(t *testing.T) {
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes(KeyToken, []byte("token")))
	require.NoError(t, enc.EncodeBytes(KeyError, []byte("error")))

	_, err := DecodeAuthOutput(buf.Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot have both token and error")
}

func TestDecodeAuthOutput_NeitherTokenNorError(t *testing.T) {
	// Only state, no token or error - build with encoder to ensure correct format
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	require.NoError(t, enc.EncodeBytes(KeyState, []byte("some-state")))

	_, err := DecodeAuthOutput(buf.Bytes())
	require.Error(t, err)
	require.Contains(t, err.Error(), "must have either token or error")
}

func TestAuth_New(t *testing.T) {
	auth := NewAuth("my-auth-command --flag")
	require.NotNil(t, auth)
	require.Equal(t, "my-auth-command --flag", auth.cmdLine)
	require.Empty(t, auth.state)
}

func TestAuth_Run_Success_InitialAuth(t *testing.T) {
	// Create a test auth script that returns a token
	script := writeTestScript(t, `#!/bin/sh
# Read and ignore stdin
cat > /dev/null

# Return token (using printf to avoid newline issues)
printf '%s' "11:tmy-token-1,"
`)

	auth := NewAuth(script)
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "my-token-1", token)
	require.Empty(t, auth.state) // No state returned
}

func TestAuth_Run_Success_WithStateUpdate(t *testing.T) {
	script := writeTestScript(t, `#!/bin/sh
# Read and ignore stdin
cat > /dev/null

# Return token and new state
printf '%s' "11:tmy-token-2,"
printf '%s' "18:s{\"refresh\":\"xyz\"},"
`)

	auth := NewAuth(script)
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "my-token-2", token)
	require.Equal(t, []byte(`{"refresh":"xyz"}`), auth.state)
}

func TestAuth_Run_Success_StatePreservedAcrossCalls(t *testing.T) {
	// First call returns token and state
	script1 := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:ttoken,"
printf '%s' "12:s{\"count\":1},"
`)

	auth := NewAuth(script1)
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "token", token)
	require.Equal(t, []byte(`{"count":1}`), auth.state)

	// Second call uses the state from first call
	script2 := writeTestScript(t, `#!/bin/sh
# Verify we received state on stdin
input=$(cat)
if echo "$input" | grep -q "count"; then
    printf '%s' "12:ttoken-fresh,"
    printf '%s' "12:s{\"count\":2},"
else
    printf '%s' "17:eExpected state!,"
fi
`)

	auth.cmdLine = script2
	token, err = auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "token-fresh", token)
	require.Equal(t, []byte(`{"count":2}`), auth.state)
}

func TestAuth_Run_AuthFailure(t *testing.T) {
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "22:eAuthentication failed,"
`)

	auth := NewAuth(script)
	_, err := auth.Run(nil)
	require.Error(t, err)
	require.Equal(t, "Authentication failed", err.Error())
}

func TestAuth_Run_CommandExecutionError(t *testing.T) {
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

func TestAuth_Run_InvalidOutput(t *testing.T) {
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "not a valid netstring"
`)

	auth := NewAuth(script)
	_, err := auth.Run(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode auth output")
}

func TestAuth_Run_MustacheTemplateRendering(t *testing.T) {
	// Test that mustache template is rendered in command line
	// Template renders "ok" (2 chars) so "token-ok" is 8 chars, plus 't' key = 9 total
	auth := NewAuth(`printf '%s' "9:ttoken-{{host}},"`)
	token, err := auth.Run(map[string]string{"host": "ok"})
	require.NoError(t, err)
	require.Equal(t, "token-ok", token)
}

func TestAuth_Run_MustacheTemplateError(t *testing.T) {
	auth := NewAuth("echo {{unclosed}")
	_, err := auth.Run(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to render command template")
}

func TestAuth_Run_Concurrent(t *testing.T) {
	// Test that concurrent calls are properly serialized by the lock
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
sleep 0.05
printf '%s' "6:ttoken,"
printf '%s' "12:s{\"count\":1},"
`)

	auth := NewAuth(script)

	// Run two calls concurrently
	done := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := auth.Run(nil)
			require.NoError(t, err)
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
	// Test that empty state is sent as "0:," on first call
	script := writeTestScript(t, `#!/bin/sh
input=$(cat)
if [ "$input" = "0:," ]; then
    printf '%s' "17:tfirst-call-token,"
else
    printf '%s' "19:eExpected empty state,"
fi
`)

	auth := NewAuth(script)
	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "first-call-token", token)
}

func TestAuth_Run_StateClearing(t *testing.T) {
	// Test that plugin can clear state by returning empty state
	script := writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "6:ttoken,"
# No state field - should clear existing state
`)

	auth := NewAuth(script)
	auth.state = []byte("old-state") // Set some initial state

	token, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, "token", token)
	require.Empty(t, auth.state) // State should be cleared
}

func TestRoundTrip_EncodeDecodeEmpty(t *testing.T) {
	// Test roundtrip: empty state -> encode -> decode
	encoded, err := EncodeAuthInput([]byte{})
	require.NoError(t, err)

	// Can't decode "0:," as it has no token/error, but verify the encoding
	require.Equal(t, "0:,", string(encoded))
}

func TestRoundTrip_EncodeDecodeWithState(t *testing.T) {
	// Test roundtrip: state -> encode -> use in output -> decode
	originalState := []byte(`{"token":"refresh123","exp":1234567890}`)

	// Encode as input
	encoded, err := EncodeAuthInput(originalState)
	require.NoError(t, err)

	// Verify it decodes correctly
	dec := netstring.NewDecoder(bytes.NewReader(encoded))
	key, value, err := dec.DecodeKeyed()
	require.NoError(t, err)
	require.Equal(t, byte(KeyState), byte(key))
	require.Equal(t, originalState, value)
}

func TestIntegration_FullAuthFlow(t *testing.T) {
	// Integration test: simulate a full auth flow with state management

	// First auth call - no state, returns token and state
	script1 := writeTestScript(t, `#!/bin/sh
input=$(cat)
if [ "$input" = "0:," ]; then
    # Initial auth - return token and state
    printf '%s' "19:tinitial-auth-token,"
    printf '%s' "27:s{\"refresh\":\"r1\",\"exp\":100},"
else
    printf '%s' "29:eExpected initial empty state,"
fi
`)

	auth := NewAuth(script1)
	token, err := auth.Run(map[string]string{"user": "alice"})
	require.NoError(t, err)
	require.Equal(t, "initial-auth-token", token)
	require.NotEmpty(t, auth.state)

	// Second auth call - uses state from first call
	script2 := writeTestScript(t, `#!/bin/sh
input=$(cat)
# Check that we got state with refresh token
if echo "$input" | grep -q "refresh.*r1"; then
    # Token refresh - return new token and updated state
    printf '%s' "20:trefreshed-token-123,"
    printf '%s' "27:s{\"refresh\":\"r2\",\"exp\":200},"
else
    printf '%s' "23:eExpected refresh state,"
fi
`)

	auth.cmdLine = script2
	token, err = auth.Run(map[string]string{"user": "alice"})
	require.NoError(t, err)
	require.Equal(t, "refreshed-token-123", token)
	require.Contains(t, string(auth.state), "r2")

	// Third auth call - simulate token expiration, auth fails
	script3 := writeTestScript(t, `#!/bin/sh
input=$(cat)
if echo "$input" | grep -q "refresh.*r2"; then
    # Simulate refresh token expired
    printf '%s' "45:eRefresh token expired, full re-auth required,"
    # State could be preserved or cleared - plugin's choice
    printf '%s' "1:s,"
else
    printf '%s' "23:eExpected refresh state,"
fi
`)

	auth.cmdLine = script3
	_, err = auth.Run(nil)
	require.Error(t, err)
	require.Equal(t, "Refresh token expired, full re-auth required", err.Error())
	// State should NOT be updated on error - the code returns early before state update
	// So the state from the previous successful call should still be present
	require.Equal(t, []byte(`{"refresh":"r2","exp":200}`), auth.state)
}
