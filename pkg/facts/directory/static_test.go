package directory_test

import (
	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/stretchr/testify/require"
)

func TestStaticDirectoryIgnoresHostSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "facts.yaml")
	users := "users:\n  - id: alice\n    groups: [{name: [ops]}]\n  - id: disabled\n    active: false\n"
	load := func(hosts string) *directory.Static {
		require.NoError(t, os.WriteFile(path, []byte(users+hosts), 0600))
		store, err := directory.NewStatic([]string{path})
		require.NoError(t, err)
		return store
	}
	first := load("hosts:\n  - names: []\n    pattern: '**invalid'\n    principal-mode: invalid\n    realm: undeclared\n")
	second := load("hosts:\n  - names: [other]\nrealms: [other]\n")
	user, err := first.LookupUser(t.Context(), "alice")
	require.NoError(t, err)
	require.True(t, user.Active)
	require.Equal(t, []string{"ops"}, object.GroupNames(user.Facts().Groups))

	other, err := second.LookupUser(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, user, other)
	inactive, err := first.LookupUser(t.Context(), "disabled")
	require.NoError(t, err)
	require.False(t, inactive.Active)
	missing, err := first.LookupUser(t.Context(), "missing")
	require.NoError(t, err)
	require.Nil(t, missing)

}

func TestStaticDirectoryStillRejectsUnknownFields(t *testing.T) {
	for _, body := range []string{
		"users:\n  - id: alice\n    grops: [ops]\n",
		"hosts:\n  - names: [host]\n    typo: value\n",
	} {
		path := filepath.Join(t.TempDir(), "facts.yaml")
		require.NoError(t, os.WriteFile(path, []byte(body), 0600))
		_, err := directory.NewStatic([]string{path})
		require.ErrorContains(t, err, "field")
	}
}

func TestStaticObjectFactsAndValidation(t *testing.T) {
	for _, tc := range []struct {
		fields  string
		invalid bool
	}{
		{`    name: [alice, a@example.com]
    attributes: {role: [developer, oncall], empty: "", missing: null}
    groups: [{name: [ops], attributes: {region: west}}]
`, false},
		{"    attributes: {role: 42}\n", true},
		{"    attributes: {role: [ops, null]}\n", true},
		{"    attributes: {name: forged}\n", true},
		{"    name: [alice, null]\n", true},
		{"    groups: [null]\n", true},
		{"    groups: [{name: [ops], attributes: {id: forged}}]\n", true},
	} {
		path := filepath.Join(t.TempDir(), "facts.yaml")
		require.NoError(t, os.WriteFile(path, []byte("users:\n  - id: subject\n"+tc.fields), 0600))
		dir, err := directory.NewStatic([]string{path})
		if tc.invalid {
			require.Error(t, err, tc.fields)
			continue
		}
		require.NoError(t, err)
		user, err := dir.LookupUser(t.Context(), "subject")
		require.NoError(t, err)
		facts := user.Facts()
		require.Equal(t, []string{"alice", "a@example.com"}, []string(facts.Names))
		require.Equal(t, object.Values{"developer", "oncall"}, facts.Attributes["role"])
		require.Empty(t, facts.Groups[0].ID)

	}
}
