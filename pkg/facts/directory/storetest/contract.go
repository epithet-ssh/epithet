// Package storetest tests the public directory storage and lookup contracts.
// It does not require an HTTP server or knowledge of a backend's schema,
// resource ID format, revision encoding, or persistence mechanism.
package storetest

import (
	"fmt"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"github.com/stretchr/testify/require"
)

// Backend pairs the lookup and management views of one logical directory.
// The views may be implemented by different instances.
type Backend struct {
	directory.Directory
	directory.Store
}

// Factory returns a fresh, empty directory for each subtest. It initializes
// storage and registers any cleanup with t.Cleanup. The sequential examples
// expect a test fixture whose completed writes are readable; a backend with
// delayed visibility can supply a test view that waits for its own propagation.
// This test fixture assumption is not a consistency guarantee of Store.
type Factory func(t *testing.T) Backend

// Run exercises sequential provisioning, authorization projections, pagination
// and audit through public interfaces. It does not test or define
// transactionality, concurrent access, or propagation timing. Backend-specific
// consistency, durability and HTTP protocol checks belong in separate tests.
func Run(t *testing.T, open Factory) {
	t.Helper()
	t.Run("missing resource reads", func(t *testing.T) {
		store := open(t)
		user, err := store.GetUser(t.Context(), "missing")
		require.NoError(t, err, "GetUser must return nil, nil for an absent resource ID")
		require.Nil(t, user, "GetUser must not return a zero-valued record for an absent resource ID")
		group, err := store.GetGroup(t.Context(), "missing")
		require.NoError(t, err, "GetGroup must return nil, nil for an absent resource ID")
		require.Nil(t, group, "GetGroup must not return a zero-valued record for an absent resource ID")
	})

	t.Run("user and membership lifecycle", func(t *testing.T) {
		store := open(t)
		ctx := t.Context()
		missing, err := store.LookupUser(ctx, "subject")
		require.NoError(t, err, "LookupUser on an empty directory must succeed even when the user is absent")
		require.Nil(t, missing, "LookupUser must return nil for an absent authentication ID")

		input := directory.ManagedUser{
			Metadata:   directory.Metadata{ID: "subject", Version: "caller-version", Created: time.Unix(1, 0), Modified: time.Unix(1, 0)},
			ExternalID: "upstream", UserName: "Alice", Active: true,
			UserType: "employee", Department: "engineering", Organization: "example",
		}
		u, err := store.CreateUser(ctx, input, directory.NewAuditEvent(ctx, "create", input.ID))
		require.NoError(t, err, "CreateUser must preserve the supplied ID, Created and Modified")
		checkMetadata(t, store.SupportsVersioning(), "CreateUser", u.Metadata)
		require.Equal(t, input.ID, u.ID, "CreateUser must preserve the ID resolved by its caller")
		require.True(t, input.Created.Equal(u.Created), "CreateUser must preserve the caller-supplied Created timestamp")
		require.True(t, input.Modified.Equal(u.Modified), "CreateUser must preserve the caller-supplied Modified timestamp")
		require.NotEqual(t, input.Version, u.Version, "CreateUser must not preserve caller-supplied Version")
		input.Metadata = u.Metadata
		require.Equal(t, input, u, "CreateUser must preserve all supplied profile fields, including spelling and Active")
		stored, err := store.GetUser(ctx, u.ID)
		require.NoError(t, err, "GetUser must find the newly created user by resource ID")
		require.NotNil(t, stored)
		require.True(t, u.Created.Equal(stored.Created), "GetUser must preserve the Created instant")
		require.True(t, u.Modified.Equal(stored.Modified), "GetUser must preserve the Modified instant")
		// Storage may change a timestamp's location while preserving its instant.
		record := *stored
		record.Created, record.Modified = u.Created, u.Modified
		require.Equal(t, u, record, "GetUser must return the same provisioning record that CreateUser returned")
		facts, err := store.LookupUser(ctx, "subject")
		require.NoError(t, err, "LookupUser must find the newly created user by ID")

		require.NotNil(t, facts, "LookupUser must return the user stored under this ID")
		require.Equal(t, "subject", facts.ID, "LookupUser must preserve ManagedUser.ID as User.ID")
		require.Equal(t, "Alice", facts.UserName, "LookupUser must preserve the stored UserName")
		require.True(t, facts.Active, "LookupUser must preserve Active=true")
		require.Equal(t, "employee", facts.UserType, "LookupUser must include the stored UserType")
		require.Equal(t, "engineering", facts.Department, "LookupUser must include the stored Department")
		require.Equal(t, "example", facts.Organization, "LookupUser must include the stored Organization")
		require.Empty(t, facts.Groups, "A newly created user must have no group memberships")
		for _, key := range []string{u.ExternalID, u.UserName} {
			missing, err := store.LookupUser(ctx, key)
			require.NoError(t, err, "LookupUser(%q) must succeed when the key is not an authentication ID", key)
			require.Nil(t, missing, "LookupUser(%q) must return nil: external IDs and user names are not lookup aliases", key)
		}
		g, err := store.CreateGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-ops", Created: input.Created, Modified: input.Modified, Version: "caller-version"}, DisplayName: "ops", ExternalID: "team", MemberIDs: []string{u.ID}}, directory.NewAuditEvent(ctx, "create", "group-ops"))
		require.NoError(t, err, "CreateGroup must accept a reference to an existing user")
		require.Equal(t, "group-ops", g.ID, "CreateGroup must preserve the caller-supplied resource ID")
		checkMetadata(t, store.SupportsVersioning(), "CreateGroup", g.Metadata)
		require.True(t, input.Created.Equal(g.Created), "CreateGroup must preserve the caller-supplied Created timestamp")
		require.True(t, input.Modified.Equal(g.Modified), "CreateGroup must preserve the caller-supplied Modified timestamp")
		require.NotEqual(t, "caller-version", g.Version, "CreateGroup must not preserve caller-supplied Version")
		require.Equal(t, []string{u.ID}, g.MemberIDs, "CreateGroup must preserve the supplied membership")
		facts, err = store.LookupUser(ctx, "subject")
		require.NoError(t, err, "LookupUser must succeed after adding the user to a group")
		require.NotNil(t, facts, "Adding a group membership must leave the user available to LookupUser")
		require.Equal(t, []directory.Group{{ID: g.ID, Names: []string{"ops"}, Attributes: object.Attributes{"externalId": {"team"}}}}, facts.Groups, "LookupUser must project each membership using the group resource ID, current display name, and externalId attribute")
		g, err = store.ReplaceGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: g.ID, Created: time.Unix(99, 0), Modified: time.Unix(2, 0), Version: "ignored"}, DisplayName: "renamed", MemberIDs: []string{u.ID}}, g.Version, directory.NewAuditEvent(ctx, "replace", g.ID))
		require.NoError(t, err, "ReplaceGroup must allow renaming a group with its current version")
		require.True(t, input.Created.Equal(g.Created), "ReplaceGroup must retain the stored Created timestamp")
		require.True(t, time.Unix(2, 0).Equal(g.Modified), "ReplaceGroup must preserve the supplied Modified timestamp")
		require.NotEqual(t, "ignored", g.Version, "ReplaceGroup must not preserve caller-supplied Version")
		updated, err := store.ReplaceUser(ctx, directory.ManagedUser{Metadata: directory.Metadata{ID: u.ID, Version: "ignored", Created: time.Unix(99, 0), Modified: time.Unix(2, 0)}, ExternalID: "new-subject", UserName: "Renamed"}, u.Version, directory.NewAuditEvent(ctx, "replace", u.ID))
		require.NoError(t, err, "ReplaceUser must allow changing ExternalID and UserName with its current version")
		require.Equal(t, u.ID, updated.ID, "ReplaceUser must retain the resource ID")
		require.True(t, u.Created.Equal(updated.Created), "ReplaceUser must retain the original Created timestamp")
		require.True(t, time.Unix(2, 0).Equal(updated.Modified), "ReplaceUser must preserve the supplied Modified timestamp")
		if store.SupportsVersioning() {
			require.NotEqual(t, updated.Version, u.Version, "ReplaceUser must change the resource version")
		} else {
			require.Empty(t, updated.Version)
		}
		require.False(t, updated.Active, "ReplaceUser is a full replacement: omitted Active must become false")
		require.Empty(t, updated.UserType, "ReplaceUser is a full replacement: omitted UserType must be cleared")
		require.Empty(t, updated.Department, "ReplaceUser is a full replacement: omitted Department must be cleared")
		require.Empty(t, updated.Organization, "ReplaceUser is a full replacement: omitted Organization must be cleared")
		missing, err = store.LookupUser(ctx, "new-subject")
		require.NoError(t, err, "LookupUser must succeed when ExternalID does not name a stored ID")
		require.Nil(t, missing, "Changing ExternalID must not create a lookup alias")
		facts, err = store.LookupUser(ctx, u.ID)
		require.NoError(t, err, "LookupUser must succeed under the unchanged ID")
		require.NotNil(t, facts, "Changing ExternalID must preserve lookup under the original ID")
		require.False(t, facts.Active, "LookupUser must return the inactive user with Active=false")
		require.Equal(t, []directory.Group{{ID: g.ID, Names: []string{"renamed"}}}, facts.Groups, "Changing a user's ExternalID must preserve memberships; group rename and cleared ExternalID must appear in lookup facts")
		require.NoError(t, store.DeleteUser(ctx, u.ID, "", time.Unix(3, 0), directory.NewAuditEvent(ctx, "delete", u.ID)), "DeleteUser without a version precondition must delete an existing user")
		deletedUser, err := store.GetUser(ctx, u.ID)
		require.NoError(t, err, "GetUser must succeed when the user is absent after deletion")
		require.Nil(t, deletedUser, "GetUser must return nil after the user is deleted")
		missing, err = store.LookupUser(ctx, u.ID)
		require.NoError(t, err, "LookupUser must succeed when looking up a deleted user")
		require.Nil(t, missing, "LookupUser must return nil after the user is deleted")
		cleaned, err := store.GetGroup(ctx, g.ID)
		require.NoError(t, err, "Deleting a user must leave its groups readable")
		require.NotNil(t, cleaned, "Deleting a user must retain the groups it belonged to")
		require.Empty(t, cleaned.MemberIDs, "Deleting a user must remove its membership from every group")
		if store.SupportsVersioning() {
			require.NotEqual(t, cleaned.Version, g.Version, "Removing a deleted user's membership must change the affected group's Version")
		} else {
			require.Empty(t, cleaned.Version)
		}
		require.True(t, time.Unix(3, 0).Equal(cleaned.Modified), "Membership cleanup must apply the timestamp supplied to DeleteUser")
		require.Equal(t, g.DisplayName, cleaned.DisplayName, "Membership cleanup must retain the group's DisplayName")
		recreated, err := store.CreateUser(ctx, directory.ManagedUser{Metadata: directory.Metadata{ID: "new-subject"}, ExternalID: "new-subject", UserName: "Renamed"}, directory.NewAuditEvent(ctx, "create", "new-subject"))
		require.NoError(t, err, "Deleting a user must release its UserName for a new user")
		require.NotEqual(t, u.ID, recreated.ID, "Creating a different user must preserve its distinct supplied ID")
		g, err = store.ReplaceGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: g.ID}, DisplayName: "ops", MemberIDs: []string{recreated.ID}}, "", directory.NewAuditEvent(ctx, "replace", g.ID))
		require.NoError(t, err, "ReplaceGroup must accept the recreated user's resource ID without a match precondition")
		require.NoError(t, store.DeleteGroup(ctx, g.ID, g.Version, directory.NewAuditEvent(ctx, "delete", g.ID)), "DeleteGroup must accept the group's current version")
		deletedGroup, err := store.GetGroup(ctx, g.ID)
		require.NoError(t, err, "GetGroup must succeed when the group is absent after deletion")
		require.Nil(t, deletedGroup, "GetGroup must return nil after the group is deleted")
		facts, err = store.LookupUser(ctx, "new-subject")
		require.NoError(t, err, "LookupUser must succeed after deleting one of its groups")
		require.NotNil(t, facts, "Deleting a group must leave its member users intact")
		require.Empty(t, facts.Groups, "Deleting a group must remove that group from its members' lookup facts")
	})

	t.Run("external IDs are optional attributes, not identities", func(t *testing.T) {
		store := open(t)
		for _, input := range []directory.ManagedUser{
			{Metadata: directory.Metadata{ID: "one"}, UserName: "alice", ExternalID: "shared"},
			{Metadata: directory.Metadata{ID: "two"}, UserName: "bob", ExternalID: "shared"},
			{Metadata: directory.Metadata{ID: "three"}, UserName: "charlie"},
		} {
			created, err := store.CreateUser(t.Context(), input, directory.NewAuditEvent(t.Context(), "create", input.ID))
			require.NoError(t, err, "CreateUser must accept an absent or duplicate ExternalID; ID=%q", input.ID)
			require.Equal(t, input.ID, created.ID, "CreateUser must preserve the supplied identity")
			facts, err := store.LookupUser(t.Context(), input.ID)
			require.NoError(t, err, "LookupUser must use the supplied ID")
			require.NotNil(t, facts, "Every created ID must be available for lookup")
			require.Equal(t, input.ID, facts.ID, "LookupUser must return the stored ID without mapping ExternalID")
		}
		missing, err := store.LookupUser(t.Context(), "shared")
		require.NoError(t, err, "LookupUser must not interpret ExternalID")
		require.Nil(t, missing, "ExternalID must not be a lookup alias")
		updated, err := store.ReplaceUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "one"}, UserName: "alice"}, "", directory.NewAuditEvent(t.Context(), "replace", "one"))
		require.NoError(t, err, "ReplaceUser(ID=one, ExternalID=empty, expectedVersion=empty) must succeed; empty expectedVersion disables version checking")
		require.Equal(t, "one", updated.ID, "Clearing ExternalID must preserve ID")
		require.Empty(t, updated.ExternalID, "Replacement must clear omitted ExternalID")
	})

	t.Run("pagination and memberships", func(t *testing.T) {
		assertGroup := func(expected, actual directory.ManagedGroup) {
			t.Helper()
			require.ElementsMatch(t, expected.MemberIDs, actual.MemberIDs, "Group membership contents must be preserved regardless of order")
			expected.MemberIDs, actual.MemberIDs = nil, nil
			require.Equal(t, expected, actual, "Group attributes and metadata must be preserved")
		}
		store := open(t)
		ctx := t.Context()
		var users []directory.ManagedUser
		var groups []directory.ManagedGroup
		for n := 0; n < 3; n++ {
			u, err := store.CreateUser(ctx, directory.ManagedUser{Metadata: directory.Metadata{ID: fmt.Sprint(n)}, ExternalID: fmt.Sprint(n), UserName: fmt.Sprint(n), Active: n != 0}, directory.NewAuditEvent(ctx, "create", fmt.Sprint(n)))
			require.NoError(t, err, "CreateUser must create pagination fixture %d, including inactive users", n)
			users = append(users, u)
		}
		members := []string{users[2].ID, users[0].ID}
		for n := 0; n < 3; n++ {
			g, err := store.CreateGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: fmt.Sprintf("group-%d", n)}, DisplayName: fmt.Sprint(2 - n), MemberIDs: members}, directory.NewAuditEvent(ctx, "create", fmt.Sprintf("group-%d", n)))
			require.NoError(t, err, "CreateGroup must accept unordered membership IDs for pagination fixture %d", n)
			require.ElementsMatch(t, members, g.MemberIDs, "CreateGroup must preserve membership contents regardless of order")
			groups = append(groups, g)
		}
		// Establish the backend's traversal order without imposing a sort key.
		listedUsers, total, err := store.ListUsers(ctx, 1, 10)
		require.NoError(t, err)
		require.Equal(t, len(users), total)
		require.ElementsMatch(t, users, listedUsers, "ListUsers must return the created records, including inactive users")
		listedGroups, total, err := store.ListGroups(ctx, 1, 10)
		require.NoError(t, err)
		require.Equal(t, len(groups), total)
		expectedIDs := make([]string, len(groups))
		listedIDs := make([]string, len(listedGroups))
		for i, group := range groups {
			expectedIDs[i] = group.ID
		}
		for i, group := range listedGroups {
			listedIDs[i] = group.ID
		}
		require.ElementsMatch(t, expectedIDs, listedIDs, "ListGroups must return each created group once")
		for _, listed := range listedGroups {
			for _, created := range groups {
				if listed.ID == created.ID {
					assertGroup(created, listed)
				}
			}
		}
		for _, tc := range []struct{ start, count, lo, hi int }{
			{1, 10, 0, 3}, {1, 0, 0, 0}, {2, 1, 1, 2}, {3, 10, 2, 3}, {4, 2, 3, 3},
		} {
			page, total, err := store.ListUsers(ctx, tc.start, tc.count)
			require.NoError(t, err, "ListUsers(start=%d, count=%d) must accept valid one-based pagination, including count=0 and starts beyond the end", tc.start, tc.count)
			require.Equal(t, 3, total, "ListUsers(start=%d, count=%d) must return the total before pagination, including inactive users", tc.start, tc.count)
			require.Len(t, page, tc.hi-tc.lo, "ListUsers must return the requested page size")
			for i, user := range page {
				require.Equal(t, listedUsers[tc.lo+i], user, "ListUsers must return the requested records in the backend's traversal order")
			}
			groupPage, total, err := store.ListGroups(ctx, tc.start, tc.count)
			require.NoError(t, err, "ListGroups(start=%d, count=%d) must accept valid one-based pagination, including count=0 and starts beyond the end", tc.start, tc.count)
			require.Equal(t, 3, total, "ListGroups(start=%d, count=%d) must return the total before pagination", tc.start, tc.count)
			require.Len(t, groupPage, tc.hi-tc.lo, "ListGroups must return the requested page")
			for i, group := range groupPage {
				assertGroup(listedGroups[tc.lo+i], group)
			}
		}
		for _, bounds := range [][2]int{{0, 1}, {-1, 1}, {1, -1}} {
			_, _, err := store.ListUsers(ctx, bounds[0], bounds[1])
			require.Error(t, err, "ListUsers(start=%d, count=%d) must reject start below 1 or negative count", bounds[0], bounds[1])
			_, _, err = store.ListGroups(ctx, bounds[0], bounds[1])
			require.Error(t, err, "ListGroups(start=%d, count=%d) must reject start below 1 or negative count", bounds[0], bounds[1])
		}
		got, err := store.GetGroup(ctx, groups[0].ID)
		require.NoError(t, err, "GetGroup must return the created group")
		require.NotNil(t, got)
		assertGroup(groups[0], *got)
		_, err = store.ReplaceGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: got.ID}, DisplayName: got.DisplayName}, "", directory.NewAuditEvent(ctx, "replace", got.ID))
		require.NoError(t, err, "ReplaceGroup must accept omitted MemberIDs as an empty replacement membership set")
		got, err = store.GetGroup(ctx, got.ID)
		require.NoError(t, err, "GetGroup must succeed after clearing all memberships")
		require.NotNil(t, got, "Clearing memberships must retain the group")
		require.Empty(t, got.MemberIDs, "ReplaceGroup with omitted MemberIDs must remove all existing memberships")
	})

	t.Run("audit preserves supplied events after deletion", func(t *testing.T) {
		store := open(t)
		ctx := directory.WithActor(t.Context(), "context-actor-is-not-the-event")
		events := []directory.AuditEvent{
			{Time: time.Unix(10, 0).UTC(), Actor: "importer", Action: "import", ID: "subject", Alias: "alice"},
			{Time: time.Unix(10, 0).UTC(), Actor: "admin", Action: "replace", ID: "subject"},
			{Time: time.Unix(5, 0).UTC(), Actor: "provisioner", Action: "create", ID: "group"},
			{Time: time.Unix(40, 0).UTC(), Actor: "admin", Action: "replace", ID: "group", PreviousID: "prior"},
			{Time: time.Unix(50, 0).UTC(), Actor: "admin", Action: "delete", ID: "subject"},
			{Time: time.Unix(60, 0).UTC(), Actor: "admin", Action: "delete", ID: "group"},
		}
		u, err := store.CreateUser(ctx, directory.ManagedUser{Metadata: directory.Metadata{ID: "subject"}, UserName: "alice"}, events[0])
		require.NoError(t, err)
		_, err = store.ReplaceUser(ctx, u, "", events[1])
		require.NoError(t, err)
		g, err := store.CreateGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: "group"}, DisplayName: "ops", MemberIDs: []string{u.ID}}, events[2])
		require.NoError(t, err)
		_, err = store.ReplaceGroup(ctx, g, "", events[3])
		require.NoError(t, err)
		require.NoError(t, store.DeleteUser(ctx, u.ID, "", events[4].Time, events[4]))
		require.NoError(t, store.DeleteGroup(ctx, g.ID, "", events[5]))
		var actual []directory.AuditEvent
		var cursor string
		for {
			page, next, err := store.Audit(ctx, cursor, 2)
			require.NoError(t, err)
			require.LessOrEqual(t, len(page), 2)
			actual = append(actual, page...)
			cursor = next
			if cursor == "" {
				break
			}
		}
		require.ElementsMatch(t, events, actual, "Storage must preserve every supplied event, including those for deleted resources")
		for _, limit := range []int{-1, directory.MaxAuditLimit + 1} {
			_, _, err := store.Audit(ctx, "", limit)
			require.ErrorIs(t, err, directory.ErrInvalid)
		}
	})

	t.Run("group creation preserves IDs and rejects collisions", func(t *testing.T) {
		store := open(t)
		ctx := t.Context()
		group, err := store.CreateGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: "assigned-group"}, DisplayName: "original"}, directory.NewAuditEvent(ctx, "create", "assigned-group"))
		require.NoError(t, err)
		require.Equal(t, "assigned-group", group.ID, "CreateGroup must preserve the supplied ID")
		user, err := store.CreateUser(ctx, directory.ManagedUser{Metadata: directory.Metadata{ID: "assigned-user"}, UserName: "alice"}, directory.NewAuditEvent(ctx, "create", "assigned-user"))
		require.NoError(t, err)
		for _, id := range []string{group.ID, user.ID} {
			_, err := store.CreateGroup(ctx, directory.ManagedGroup{Metadata: directory.Metadata{ID: id}, DisplayName: "replacement"}, directory.NewAuditEvent(ctx, "create", id))
			require.ErrorIs(t, err, directory.ErrConflict, "CreateGroup(ID=%q) must reject an ID already owned by a user or group", id)
		}
		got, err := store.GetGroup(ctx, group.ID)
		require.NoError(t, err)
		require.Equal(t, &group, got, "A duplicate group creation must not replace the existing group or its metadata")
		gotUser, err := store.GetUser(ctx, user.ID)
		require.NoError(t, err)
		require.Equal(t, &user, gotUser, "A group creation colliding with a user must leave that user unchanged")
	})

}

func checkMetadata(t *testing.T, versioned bool, operation string, m directory.Metadata) {
	t.Helper()
	require.NotEmpty(t, m.ID, "%s must return a nonempty resource ID", operation)
	if versioned {
		require.NotEmpty(t, m.Version, "%s must assign a resource Version when supported", operation)
	} else {
		require.Empty(t, m.Version, "%s must omit Version when unsupported", operation)
	}
}
