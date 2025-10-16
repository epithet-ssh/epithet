package broker

import (
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

// TestEncodeAuthInput tests encoding of auth input (stdin to auth command)
func TestEncodeAuthInput(t *testing.T) {
	tests := []struct {
		name     string
		state    []byte
		expected string
	}{
		{
			name:     "empty state",
			state:    []byte{},
			expected: "0:,", // Empty netstring
		},
		{
			name:     "nil state",
			state:    nil,
			expected: "0:,", // Empty netstring
		},
		{
			name:     "simple state",
			state:    []byte("refresh_token_123"),
			expected: "18:srefresh_token_123,",
		},
		{
			name:     "json state",
			state:    []byte(`{"refresh":"abc"}`),
			expected: `18:s{"refresh":"abc"},`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EncodeAuthInput(tt.state)
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(result))
		})
	}
}

// TestDecodeAuthOutput tests decoding of auth output (stdout from auth command)
func TestDecodeAuthOutput(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedToken  []byte
		expectedState  []byte
		expectedError  string
		expectParseErr bool
	}{
		{
			name:          "token only",
			input:         "15:tjwt_token_here,",
			expectedToken: []byte("jwt_token_here"),
		},
		{
			name:          "token with state",
			input:         "15:tjwt_token_here,16:snew_refresh_123,",
			expectedToken: []byte("jwt_token_here"),
			expectedState: []byte("new_refresh_123"),
		},
		{
			name:          "error only",
			input:         "22:eauthentication failed,",
			expectedError: "authentication failed",
		},
		{
			name:          "error with state",
			input:         "14:etoken expired,10:sold_state,",
			expectedError: "token expired",
			expectedState: []byte("old_state"),
		},
		{
			name:           "both token and error - protocol violation",
			input:          "10:tsome_token,20:esome error message,",
			expectParseErr: true,
		},
		{
			name:           "neither token nor error - protocol violation",
			input:          "10:ssome_state,",
			expectParseErr: true,
		},
		{
			name:           "empty output",
			input:          "",
			expectParseErr: true,
		},
		{
			name:           "multiple tokens - protocol violation",
			input:          "7:ttoken1,7:ttoken2,",
			expectParseErr: true,
		},
		{
			name:           "multiple errors - protocol violation",
			input:          "7:eerror1,7:eerror2,",
			expectParseErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := DecodeAuthOutput([]byte(tt.input))

			if tt.expectParseErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedToken, output.Token)
			require.Equal(t, tt.expectedState, output.State)
			require.Equal(t, tt.expectedError, output.Error)
		})
	}
}

// TestAuth_Run_ProtocolValidation tests protocol-level validation
func TestAuth_Run_ProtocolValidation(t *testing.T) {
	tests := []struct {
		name        string
		script      string
		expectError string
	}{
		{
			name: "both token and error - protocol violation",
			script: `#!/bin/sh
cat > /dev/null
printf '11:tsome_token,19:esome error message,'
`,
			expectError: "protocol violation: cannot have both token and error",
		},
		{
			name: "neither token nor error - protocol violation",
			script: `#!/bin/sh
cat > /dev/null
printf '11:ssome_state,'
`,
			expectError: "protocol violation: must have either token or error field",
		},
		{
			name: "malformed netstring",
			script: `#!/bin/sh
cat > /dev/null
printf 'not-a-netstring'
`,
			expectError: "failed to decode auth output",
		},
		{
			name: "non-zero exit code",
			script: `#!/bin/sh
cat > /dev/null
printf '11:tsome_token,'
exit 1
`,
			expectError: "auth command failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := New(tt.script)
			output, err := auth.Run(nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectError)
			require.Nil(t, output)
		})
	}
}

// TestAuth_Run_Success tests successful auth flows
func TestAuth_Run_Success(t *testing.T) {
	tests := []struct {
		name          string
		script        string
		expectedToken []byte
		expectedState []byte
		expectedError string
	}{
		{
			name: "initial auth - returns token",
			script: `#!/bin/sh
cat > /dev/null
printf '15:tnew_auth_token,15:snew_state_data,'
`,
			expectedToken: []byte("new_auth_token"),
			expectedState: []byte("new_state_data"),
		},
		{
			name: "auth failure - returns error",
			script: `#!/bin/sh
cat > /dev/null
printf '26:eRefresh token has expired,'
`,
			expectedError: "Refresh token has expired",
		},
		{
			name: "token without state update",
			script: `#!/bin/sh
cat > /dev/null
printf '11:tsome_token,'
`,
			expectedToken: []byte("some_token"),
		},
		{
			name: "order doesn't matter - state then token",
			script: `#!/bin/sh
cat > /dev/null
printf '11:ssome_state,11:tsome_token,'
`,
			expectedToken: []byte("some_token"),
			expectedState: []byte("some_state"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := New(tt.script)
			output, err := auth.Run(nil)
			require.NoError(t, err)
			require.NotNil(t, output)

			if tt.expectedToken != nil {
				require.Equal(t, tt.expectedToken, output.Token)
				require.Empty(t, output.Error)
			}
			if tt.expectedError != "" {
				require.Empty(t, output.Token)
				require.Equal(t, tt.expectedError, output.Error)
			}
			if tt.expectedState != nil {
				require.Equal(t, tt.expectedState, output.State)
			}
		})
	}
}

// TestAuth_Run_StatePersistence tests that state persists across multiple Run calls
func TestAuth_Run_StatePersistence(t *testing.T) {
	// This script reads input, extracts count from state, increments it, and returns it
	script := `#!/bin/sh
# Read the netstring input
input=$(cat)

# Extract count if present (simple grep for this test)
count=$(echo "$input" | grep -o 'count:[0-9]*' | cut -d: -f2 || echo "0")

# Increment count
count=$((count + 1))

# Output token and new state
# Calculate netstring lengths carefully
state="count:$count"
state_len=$((${#state} + 1))  # +1 for 's' key
token="token_$count"
token_len=$((${#token} + 1))  # +1 for 't' key

printf "${token_len}:t${token},${state_len}:s${state},"
`

	auth := New(script)

	// First run - no prior state (will receive 0:,)
	output1, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, []byte("token_1"), output1.Token)
	require.Equal(t, []byte("count:1"), output1.State)

	// Second run - should have state from first run
	output2, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, []byte("token_2"), output2.Token)
	require.Equal(t, []byte("count:2"), output2.State)

	// Third run - should have state from second run
	output3, err := auth.Run(nil)
	require.NoError(t, err)
	require.Equal(t, []byte("token_3"), output3.Token)
	require.Equal(t, []byte("count:3"), output3.State)
}
