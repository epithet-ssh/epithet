package main

import (
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestInventoryTokenRequiresSubjectAndExplicitLifetime(t *testing.T) {
	for _, tc := range []struct {
		args                 []string
		parseError, runError bool
	}{
		{[]string{}, true, false},
		{[]string{"--subject", "provisioner"}, true, false},
		{[]string{"--expires-in", "2160h"}, true, false},
		{[]string{"--subject", "", "--expires-in", "2160h"}, false, true},
		{[]string{"--subject", "provisioner", "--expires-in", "0s"}, false, true},
		{[]string{"--subject", "provisioner", "--expires-in=-1h"}, false, true},
		{[]string{"--subject", "provisioner", "--expires-in", "2160h"}, false, false},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var command InventoryTokenCreateCLI
			parser, err := kong.New(&command)
			require.NoError(t, err)
			_, err = parser.Parse(tc.args)
			if tc.parseError {
				require.Error(t, err)
				return
			}
			// Kong may reject an explicitly empty required string itself.
			if err != nil && tc.runError {
				return
			}
			require.NoError(t, err)
			if tc.runError {
				require.Error(t, command.Run(nil))
				return
			}
			require.Equal(t, "provisioner", command.Subject)
			require.Equal(t, 2160*time.Hour, command.ExpiresIn)
		})
	}
}
