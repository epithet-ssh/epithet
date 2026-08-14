package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

// TestReadOnlyKeyringRefusesWrites pins the exact error message every
// mutating method returns - the wire-level test in agent_test.go can only
// confirm a client sees *some* failure, since the SSH agent protocol
// discards error text.
func TestReadOnlyKeyringRefusesWrites(t *testing.T) {
	r := newReadOnlyKeyring()

	require.EqualError(t, r.Add(agent.AddedKey{}), "epithet agent is read-only")
	require.EqualError(t, r.Remove(nil), "epithet agent is read-only")
	require.EqualError(t, r.RemoveAll(), "epithet agent is read-only")
	require.EqualError(t, r.Lock(nil), "epithet agent is read-only")
	require.EqualError(t, r.Unlock(nil), "epithet agent is read-only")
}

// TestReadOnlyKeyringListEmptyBeforeSwap confirms List works against the
// empty inner keyring newReadOnlyKeyring seeds before the first swap, rather
// than panicking on a nil inner pointer.
func TestReadOnlyKeyringListEmptyBeforeSwap(t *testing.T) {
	r := newReadOnlyKeyring()

	keys, err := r.List()
	require.NoError(t, err)
	require.Empty(t, keys)
}
