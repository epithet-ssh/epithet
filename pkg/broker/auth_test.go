package broker

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/stretchr/testify/require"
)

func mintValid(t *testing.T, idp *oidctest.IdP, d time.Duration) string {
	return idp.MintIDToken("t@example.com", time.Now().Add(d))
}

func TestTokenFetchesOnceWhileValid(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	a := NewAuth(func(ctx context.Context, out io.Writer, force bool) (string, error) {
		calls.Add(1)
		return mintValid(t, idp, time.Hour), nil
	})
	for range 5 {
		_, err := a.Token(context.Background(), nil)
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), calls.Load())
}

func TestTokenRefreshesProactivelyNearExpiry(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	a := NewAuth(func(ctx context.Context, out io.Writer, force bool) (string, error) {
		calls.Add(1)
		// Expires inside expiryBuffer: every call must refetch.
		return mintValid(t, idp, expiryBuffer/2), nil
	})
	_, err := a.Token(context.Background(), nil)
	require.NoError(t, err)
	_, err = a.Token(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load(), "near-expiry token must be refreshed, not reused")
}

func TestConcurrentTokenCallsShareOneFetch(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	release := make(chan struct{})
	a := NewAuth(func(ctx context.Context, out io.Writer, force bool) (string, error) {
		calls.Add(1)
		fmt.Fprint(out, "visit: https://example/auth\n")
		<-release
		return mintValid(t, idp, time.Hour), nil
	})

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.Token(context.Background(), io.Discard)
			require.NoError(t, err)
		}()
	}
	time.Sleep(100 * time.Millisecond) // Let everyone join the flight.
	close(release)
	wg.Wait()
	require.Equal(t, int32(1), calls.Load())
}

func TestForceRefreshDiscardsCachedToken(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	a := NewAuth(func(ctx context.Context, out io.Writer, force bool) (string, error) {
		calls.Add(1)
		return mintValid(t, idp, time.Hour), nil
	})
	_, _ = a.Token(context.Background(), nil)
	_, err := a.ForceRefresh(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load())
}

// TestForceRefreshReturnsAndCachesTheFetchedToken guards against the bug
// where ForceRefresh re-invoked fetch but fetch, unaware anything had
// changed, handed back the exact credential the CA had just rejected
// (pkg/auth/oidc's Authenticate returns prev unchanged while prev.Valid()).
// fetch here honors force by minting a genuinely different token, the way a
// real TokenFunc must; ForceRefresh must surface that new token, and it must
// become the cache so the next plain Token() doesn't re-fetch.
func TestForceRefreshReturnsAndCachesTheFetchedToken(t *testing.T) {
	idp := oidctest.New(t)
	first := mintValid(t, idp, time.Hour)
	second := mintValid(t, idp, time.Hour)
	var calls atomic.Int32
	a := NewAuth(func(ctx context.Context, out io.Writer, force bool) (string, error) {
		n := calls.Add(1)
		if n == 1 {
			require.False(t, force, "the initial fetch is not a forced one")
			return first, nil
		}
		require.True(t, force, "ForceRefresh must invoke fetch with force=true")
		return second, nil
	})

	tok, err := a.Token(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, first, tok)

	tok, err = a.ForceRefresh(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, second, tok, "ForceRefresh must return the freshly fetched token, not the stale cached one")

	// The new token must be cached: a subsequent Token() call must not fetch again.
	tok, err = a.Token(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, second, tok)
	require.Equal(t, int32(2), calls.Load(), "the cached post-ForceRefresh token must not trigger a third fetch")
}

func TestParseJWTExpiry(t *testing.T) {
	idp := oidctest.New(t)
	exp := time.Now().Add(7 * time.Minute).Truncate(time.Second)
	got, err := parseJWTExpiry(idp.MintIDToken("x@y.z", exp))
	require.NoError(t, err)
	require.WithinDuration(t, exp, got, time.Second)

	_, err = parseJWTExpiry("not-a-jwt")
	require.Error(t, err)
}

// waitForWaiters polls until the in-flight fetch has n attached waiters.
func waitForWaiters(t *testing.T, a *Auth, n int) *authFlight {
	t.Helper()
	var flight *authFlight
	require.Eventually(t, func() bool {
		a.mu.Lock()
		flight = a.inflight
		a.mu.Unlock()
		if flight == nil {
			return false
		}
		flight.mu.Lock()
		defer flight.mu.Unlock()
		return flight.waiters == n
	}, 5*time.Second, 10*time.Millisecond, "waiting for %d waiters", n)
	return flight
}

// TestAbandonedFlightRetriesOnSameAuth exercises the abandoned-flight retry
// loop in acquire: a second caller arriving on the SAME Auth instance after
// the sole waiter of an in-flight fetch has canceled must not join that
// dying flight (attach returns ok=false because it's abandoned) — it has to
// wait for the flight to actually wind down and then trigger a brand new
// fetch. A prior version of this test used a second, separate Auth instance
// for the "fresh attempt" half, which never exercised that retry branch at
// all (a nil a.inflight on a fresh Auth always takes the "start a new
// flight" path, never the "wait for abandoned flight, then retry" path).
func TestAbandonedFlightRetriesOnSameAuth(t *testing.T) {
	idp := oidctest.New(t)
	started := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	var fetchCtxDone atomic.Bool
	fresh := mintValid(t, idp, time.Hour)
	a := NewAuth(func(ctx context.Context, out io.Writer, force bool) (string, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-ctx.Done() // Observe the flight's own context being canceled...
			fetchCtxDone.Store(true)
			<-releaseFirst // ...but don't actually finish until the test says so,
			// so the flight is provably abandoned-but-unfinished when the
			// second caller arrives.
			return "", ctx.Err()
		}
		return fresh, nil
	})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := a.Token(leaderCtx, nil)
		leaderErr <- err
	}()
	<-started

	// Abandon the flow (e.g. user killed the ssh session). The leader is the
	// only waiter, so this cancels the flight's own context too.
	cancelLeader()
	select {
	case err := <-leaderErr:
		require.ErrorIs(t, err, context.Canceled)
		require.Contains(t, err.Error(), "authentication canceled")
	case <-time.After(5 * time.Second):
		t.Fatal("leader Token did not return after context cancelation")
	}
	require.Eventually(t, func() bool {
		return fetchCtxDone.Load()
	}, 5*time.Second, 10*time.Millisecond, "fetch was not canceled")

	// At this point the flight is abandoned but its fetch is still blocked
	// on releaseFirst (flight.done not yet closed, a.inflight not yet nil).
	// A second caller arriving now must see attach() fail and wait.
	secondStarted := make(chan struct{})
	secondDone := make(chan struct{})
	var secondToken string
	var secondErr error
	go func() {
		close(secondStarted)
		secondToken, secondErr = a.Token(context.Background(), nil)
		close(secondDone)
	}()
	<-secondStarted
	time.Sleep(100 * time.Millisecond) // Let it reach the abandoned-flight wait.

	select {
	case <-secondDone:
		t.Fatal("second Token returned before the abandoned flight wound down")
	default:
	}

	// Let the abandoned flight finish; the second caller must then retry
	// with a fresh flight rather than staying stuck behind it.
	close(releaseFirst)
	select {
	case <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("second Token did not complete after the abandoned flight finished")
	}
	require.NoError(t, secondErr)
	require.Equal(t, fresh, secondToken)
	require.Equal(t, int32(2), calls.Load(), "abandoned flight retry must trigger exactly one fresh fetch")
}

func TestJoinerKeepsFlightAliveAfterLeaderCancels(t *testing.T) {
	idp := oidctest.New(t)
	started := make(chan struct{})
	release := make(chan struct{})
	a := NewAuth(func(ctx context.Context, out io.Writer, force bool) (string, error) {
		close(started)
		fmt.Fprint(out, "visit: https://example/auth\n")
		<-release
		return mintValid(t, idp, time.Hour), nil
	})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderErr := make(chan error, 1)
	go func() {
		_, err := a.Token(leaderCtx, nil)
		leaderErr <- err
	}()
	<-started

	var joinerOut fmtBuffer
	joinerResult := make(chan string, 1)
	joinerErrCh := make(chan error, 1)
	go func() {
		token, err := a.Token(context.Background(), &joinerOut)
		joinerResult <- token
		joinerErrCh <- err
	}()
	waitForWaiters(t, a, 2)

	// Replay: the joiner sees output already emitted before it attached.
	require.Eventually(t, func() bool {
		return joinerOut.String() != ""
	}, 5*time.Second, 10*time.Millisecond, "joiner did not receive replayed output")
	require.Contains(t, joinerOut.String(), "visit: https://example/auth")

	// Leader abandons; the flight must survive for the joiner.
	cancelLeader()
	select {
	case err := <-leaderErr:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("leader Token did not return after cancelation")
	}

	close(release)
	select {
	case token := <-joinerResult:
		require.NoError(t, <-joinerErrCh)
		require.NotEmpty(t, token)
	case <-time.After(5 * time.Second):
		t.Fatal("joiner Token did not complete")
	}
}

// fmtBuffer is a minimal concurrency-safe io.Writer for assertions that poll
// its contents from a different goroutine than the one writing to it.
type fmtBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *fmtBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *fmtBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
