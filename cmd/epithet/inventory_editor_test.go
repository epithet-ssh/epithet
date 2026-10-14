package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
)

func TestEditorCancelAndValidationRetry(t *testing.T) {
	t.Setenv("EDITOR", `sh -c ': > "$1"' editor`)
	initial := inventory.Host{Names: []string{"one"}, Labels: map[string]string{}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
	_, err := editInventory(initial, bufio.NewReader(strings.NewReader("")), inventory.ParseHost)
	require.ErrorIs(t, err, errCanceled)
	t.Setenv("EDITOR", "true")
	p, err := editInventory(initial, bufio.NewReader(strings.NewReader("")), inventory.ParseHost)
	require.NoError(t, err)
	require.Equal(t, initial, p)
	script := filepath.Join(t.TempDir(), "editor")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nif [ ! -f \"$1.once\" ]; then\n touch \"$1.once\"\n printf 'invalid: yaml\\n' > \"$1\"\nelse\n rm \"$1.once\"\n printf 'names: [fixed]\\naccounts: []\\nprincipal-mode: account-name\\n' > \"$1\"\nfi\n"), 0700))
	t.Setenv("EDITOR", script)
	p, err = editInventory(initial, bufio.NewReader(strings.NewReader("edit\n")), inventory.ParseHost)
	require.NoError(t, err)
	require.Equal(t, []string{"fixed"}, p.Names)
}

// Saving unchanged YAML must preserve null account semantics.
func TestEditorPreservesUnrestrictedAccounts(t *testing.T) {
	t.Setenv("EDITOR", "true")
	initial := inventory.Host{Names: []string{"host"}, PrincipalMode: inventory.AccountNamePrincipals}
	edited, err := editInventory(initial, bufio.NewReader(strings.NewReader("")), inventory.ParseHost)
	require.NoError(t, err)
	require.Nil(t, edited.Accounts)
}
