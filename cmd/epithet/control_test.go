package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestControlTokenConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, literal, file, wantError string }{
		{name: "literal", literal: "secret"}, {name: "file", file: "secret\n"},
		{name: "disabled"}, {name: "both", literal: "secret", file: "secret", wantError: "use either"},
		{name: "empty file", file: "\n", wantError: "nonempty bearer token"},
		{name: "invalid", literal: "not a token", wantError: "without whitespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ControlCLI{SCIMToken: tc.literal}
			if tc.file != "" {
				c.SCIMTokenFile = filepath.Join(t.TempDir(), "token")
				require.NoError(t, os.WriteFile(c.SCIMTokenFile, []byte(tc.file), 0600))
			}
			token, err := c.provisioningToken()
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
				if tc.name != "disabled" {
					require.Equal(t, "secret", token)
				}
			}
		})
	}
}
