package directory_test

import (
	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/stretchr/testify/require"
)

func TestStaticDirectoryIgnoresHostSemanticsAndRevisions(t *testing.T) {
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
	user, revision, err := first.LookupUser(t.Context(), "alice")
	require.NoError(t, err)
	require.True(t, user.Active)
	require.Equal(t, []string{"ops"}, object.GroupNames(user.Groups))
	require.NotEmpty(t, revision)
	require.Equal(t, first.DirectoryRevision(), second.DirectoryRevision())
	inactive, _, err := first.LookupUser(t.Context(), "disabled")
	require.NoError(t, err)
	require.False(t, inactive.Active)
	snapshot, listedRevision, err := first.ListUserFacts(t.Context())
	require.NoError(t, err)
	require.Len(t, snapshot, 2)
	require.Equal(t, revision, listedRevision)
	missing, missingRevision, err := first.LookupUser(t.Context(), "missing")
	require.NoError(t, err)
	require.Nil(t, missing)
	require.Equal(t, revision, missingRevision)
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
		user, _, err := dir.LookupUser(t.Context(), "subject")
		require.NoError(t, err)
		facts := user.Facts()
		require.Equal(t, []string{"alice", "a@example.com"}, []string(facts.Names))
		require.Equal(t, object.Values{"developer", "oncall"}, facts.Attributes["role"])
		require.Empty(t, facts.Groups[0].ID)
		listed, _, err := dir.ListUserFacts(t.Context())
		require.NoError(t, err)
		listed[0].Attributes["role"][0] = "changed"
		listed[0].Groups[0].Attributes["region"][0] = "changed"
		require.Equal(t, "developer", facts.Attributes["role"][0])
		require.Equal(t, "west", facts.Groups[0].Attributes["region"][0])
	}
}
