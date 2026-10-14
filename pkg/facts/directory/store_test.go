package directory_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/stretchr/testify/require"
)

func TestValidateUser(t *testing.T) {
	for _, name := range []string{"Alice", "ＡLICE", "alice", "Straße"} {
		user := directory.ManagedUser{
			Metadata: directory.Metadata{ID: "subject"},
			UserName: name, ExternalID: "external",
		}
		before := user
		require.NoError(t, user.Validate())
		require.Equal(t, before, user, "Validation must not change user attributes")
	}
	for _, blank := range []string{"", " \t\n", " "} {
		user := directory.ManagedUser{Metadata: directory.Metadata{ID: blank}, UserName: "alice"}
		require.ErrorIs(t, user.Validate(), directory.ErrInvalid, "A blank ID must fail before storage")
		user.ID, user.UserName = "subject", blank
		require.ErrorIs(t, user.Validate(), directory.ErrInvalid, "A blank userName must fail before storage")
	}
}

func TestValidateGroup(t *testing.T) {
	group := directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-Ops"}, DisplayName: " Ops ", MemberIDs: []string{"subject"}}
	require.NoError(t, group.Validate())
	require.Equal(t, " Ops ", group.DisplayName)
	require.Equal(t, "group-Ops", group.ID, "Validation must preserve the supplied ID")
	require.Equal(t, []string{"subject"}, group.MemberIDs)
	for _, blank := range []string{"", " \t\n", " "} {
		group.ID, group.DisplayName = blank, "ops"
		require.ErrorIs(t, group.Validate(), directory.ErrInvalid, "A blank ID must fail before storage")
		group.ID, group.DisplayName = "group-ops", blank
		require.ErrorIs(t, group.Validate(), directory.ErrInvalid, "A blank displayName must fail before storage")
	}
}
