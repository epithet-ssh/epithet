package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAcquireProfileLockPreventsConcurrentAgents exercises the flock guard
// the same way AgentStartCLI.Run does: acquire once (as the first agent
// process would), then attempt a second acquisition against the same rundir
// (as a concurrent second process for the same --agent-name would) and confirm it
// fails with a clear, actionable error instead of silently succeeding and
// stealing the socket out from under the first process.
func TestAcquireProfileLockPreventsConcurrentAgents(t *testing.T) {
	dir := t.TempDir()

	f1, err := acquireProfileLock(dir, "work")
	require.NoError(t, err)
	t.Cleanup(func() { f1.Close() })

	_, err = acquireProfileLock(dir, "work")
	require.Error(t, err)
	require.EqualError(t, err, `profile "work" is already running (use --agent-name to run a second profile)`)
}
