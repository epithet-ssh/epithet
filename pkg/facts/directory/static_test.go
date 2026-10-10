package directory_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/stretchr/testify/require"
)

func TestStaticDirectoryIgnoresHostSemanticsAndRevisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "facts.yaml")
	users := "users:\n  - id: alice\n    groups: [ops]\n  - id: disabled\n    active: false\n"
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
	require.Equal(t, []string{"ops"}, user.Groups)
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
