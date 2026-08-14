package broker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// gatedScript writes an auth script that signals it has started, then blocks
// until the test creates the release file. It appends to a run-count file so
// tests can assert how many times the command actually executed.
func gatedScript(t *testing.T, dir string) string {
	t.Helper()
	script := fmt.Sprintf(`#!/bin/sh
cat > /dev/null
echo "run" >> %[1]s/runs
printf 'visit https://auth.example/device\n' >&4
echo $$ > %[1]s/pid
touch %[1]s/started
while [ ! -f %[1]s/release ]; do sleep 0.02; done
printf '%%s' "gated-token"
`, dir)
	return writeTestScript(t, script)
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "waiting for %s", path)
}

func runCount(t *testing.T, dir string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "runs"))
	if err != nil {
		return 0
	}
	return strings.Count(string(data), "run")
}

// waitForWaiters polls until the in-flight auth attempt has n attached waiters.
func waitForWaiters(t *testing.T, auth *Auth, n int) *authFlight {
	t.Helper()
	var flight *authFlight
	require.Eventually(t, func() bool {
		auth.lock.Lock()
		flight = auth.inflight
		auth.lock.Unlock()
		if flight == nil {
			return false
		}
		flight.mu.Lock()
		defer flight.mu.Unlock()
		return flight.waiters == n
	}, 5*time.Second, 10*time.Millisecond, "waiting for %d waiters", n)
	return flight
}

func TestAuth_Run_SingleflightSharesOneCommand(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	auth := NewAuth(gatedScript(t, dir))

	var leaderOut, joinerOut bytes.Buffer
	var wg sync.WaitGroup
	results := make([]string, 2)
	errs := make([]error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		results[0], errs[0] = auth.Run(context.Background(), nil, &leaderOut)
	}()
	waitForFile(t, filepath.Join(dir, "started"))

	wg.Add(1)
	go func() {
		defer wg.Done()
		results[1], errs[1] = auth.Run(context.Background(), nil, &joinerOut)
	}()
	waitForWaiters(t, auth, 2)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "release"), nil, 0644))
	wg.Wait()

	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	require.Equal(t, results[0], results[1])
	require.NotEmpty(t, results[0])

	// The command ran exactly once - the second caller joined the flight.
	require.Equal(t, 1, runCount(t, dir))

	// Both callers saw the user-visible auth URL, the joiner via replay.
	require.Contains(t, leaderOut.String(), "visit https://auth.example/device")
	require.Contains(t, joinerOut.String(), "visit https://auth.example/device")
}

func TestAuth_Run_CancelKillsCommandAndAllowsFreshAttempt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	auth := NewAuth(gatedScript(t, dir))

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := auth.Run(ctx, nil, nil)
		errCh <- err
	}()
	waitForFile(t, filepath.Join(dir, "started"))

	// Abandon the flow (e.g. user killed the ssh session).
	cancel()
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
		require.Contains(t, err.Error(), "authentication canceled")
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancelation")
	}

	// The auth command process must actually die.
	pidBytes, err := os.ReadFile(filepath.Join(dir, "pid"))
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return syscall.Kill(pid, 0) != nil
	}, 5*time.Second, 10*time.Millisecond, "auth command process still alive")

	// A fresh attempt (e.g. a new ssh session) starts a new command rather
	// than getting stuck behind the abandoned one.
	auth.cmdLine = writeTestScript(t, `#!/bin/sh
cat > /dev/null
printf '%s' "fresh-token"
`)
	token, err := auth.Run(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Equal(t, "fresh-token", token)
}

func TestAuth_Run_JoinerKeepsFlightAliveAfterLeaderCancels(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	auth := NewAuth(gatedScript(t, dir))

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderErr := make(chan error, 1)
	go func() {
		_, err := auth.Run(leaderCtx, nil, nil)
		leaderErr <- err
	}()
	waitForFile(t, filepath.Join(dir, "started"))

	joinerResult := make(chan string, 1)
	joinerErrCh := make(chan error, 1)
	go func() {
		token, err := auth.Run(context.Background(), nil, nil)
		joinerResult <- token
		joinerErrCh <- err
	}()
	waitForWaiters(t, auth, 2)

	// Leader abandons; the flight must survive for the joiner.
	cancelLeader()
	select {
	case err := <-leaderErr:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("leader Run did not return after cancelation")
	}

	require.NoError(t, os.WriteFile(filepath.Join(dir, "release"), nil, 0644))
	select {
	case token := <-joinerResult:
		require.NoError(t, <-joinerErrCh)
		require.Equal(t, "gated-token", token)
	case <-time.After(5 * time.Second):
		t.Fatal("joiner Run did not complete")
	}

	require.Equal(t, 1, runCount(t, dir))
}
