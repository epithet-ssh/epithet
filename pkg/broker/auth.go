package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// TokenFunc acquires a fresh JWT. force is true when the caller has already
// determined the current credential was rejected (ForceRefresh) and a
// genuinely new token is required, not merely "no cached token yet".
// Implementations backed by refreshable state (e.g. an oauth2.Token) must
// not treat force=true as an ordinary call and hand back a still-"valid"
// credential — that would silently defeat the 401 safety net. Invocations
// are serialized by Auth, so a stateful closure needs no locking of its own.
type TokenFunc func(ctx context.Context, out io.Writer, force bool) (string, error)

// Auth caches a JWT obtained from fetch and refreshes it proactively before
// it expires.
//
// Concurrency: Auth is safe for concurrent use. Concurrent Token() calls are
// coalesced (singleflight): the first caller invokes fetch, later callers
// join the in-flight attempt, receive a replay of its user-visible output so
// far, and share its result. fetch's context is canceled when every caller
// waiting on it has canceled its own context.
//
// Locking invariants:
//   - mu protects: token, expiresAt, inflight
//   - the flight goroutine writes token/expiresAt back under mu on success;
//     no other flight can start while one is in flight
//   - fetch is immutable after NewAuth()
type Auth struct {
	fetch TokenFunc // Immutable after NewAuth().

	mu        sync.Mutex // Protects token, expiresAt, inflight.
	token     string
	expiresAt time.Time
	inflight  *authFlight // Non-nil while a fetch is in flight.
}

// authFlight is a single in-flight token fetch, shared by every Token()
// caller that is waiting on it.
type authFlight struct {
	mu      sync.Mutex
	output  bytes.Buffer      // Accumulated user-visible output, replayed to joiners.
	writers map[int]io.Writer // Live user-output writers, keyed by waiter id.
	nextID  int

	forced bool // True if this flight was started by ForceRefresh; immutable after creation.

	waiters   int                // Callers currently waiting on this flight.
	abandoned bool               // Set when the last waiter cancels; no new joiners.
	cancel    context.CancelFunc // Cancels the fetch; called when waiters drops to 0.

	done  chan struct{} // Closed when the flight finishes; token/err valid after.
	token string
	err   error
}

// Write broadcasts user-visible output from fetch to every attached caller
// and records it for replay to late joiners.
func (f *authFlight) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.output.Write(p)
	for _, w := range f.writers {
		// Best effort: a dead writer is dropped when its waiter detaches.
		_, _ = w.Write(p)
	}
	return len(p), nil
}

// attach registers a caller waiting on this flight. Output produced so far
// (e.g. the "visit this URL" message) is replayed to userOutput. Returns
// ok=false without attaching if the flight has been abandoned (its fetch is
// already being canceled); the caller should wait for it to finish and start
// a fresh one.
func (f *authFlight) attach(userOutput io.Writer) (id int, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.abandoned {
		return 0, false
	}
	id = f.nextID
	f.nextID++
	f.waiters++
	if userOutput != nil {
		if f.output.Len() > 0 {
			_, _ = userOutput.Write(f.output.Bytes())
		}
		f.writers[id] = userOutput
	}
	return id, true
}

// detach removes a caller. When the last caller detaches before the flight
// finishes, the fetch is canceled — nobody is left to use its result.
func (f *authFlight) detach(id int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.writers, id)
	f.waiters--
	if f.waiters == 0 {
		f.abandoned = true
		f.cancel()
	}
}

// NewAuth creates a new Auth backed by fetch.
func NewAuth(fetch TokenFunc) *Auth {
	return &Auth{fetch: fetch}
}

// Token returns a JWT valid for at least expiryBuffer, fetching or
// refreshing it if needed. Concurrent callers share one in-flight fetch;
// joiners get a replay of its user-visible output so far.
func (a *Auth) Token(ctx context.Context, out io.Writer) (string, error) {
	a.mu.Lock()
	if a.token != "" && time.Now().Add(expiryBuffer).Before(a.expiresAt) {
		tok := a.token
		a.mu.Unlock()
		return tok, nil
	}
	a.mu.Unlock()
	return a.acquire(ctx, out, false)
}

// ForceRefresh discards the cached token and fetches a new one. This is the
// 401 safety net: the CA rejected a token we believed was still valid
// (server-side revocation, clock skew), so we bypass the cache once and tell
// fetch (via force=true) that it must not hand back that same credential.
func (a *Auth) ForceRefresh(ctx context.Context, out io.Writer) (string, error) {
	a.mu.Lock()
	a.token = ""
	a.expiresAt = time.Time{}
	a.mu.Unlock()
	return a.acquire(ctx, out, true)
}

// acquire joins an in-flight fetch or starts a new one, waiting for it to
// finish. Canceling ctx abandons this caller's wait; fetch itself is
// canceled only when every waiting caller has canceled.
//
// A force=true caller (ForceRefresh) never joins a flight that was started
// without force: that flight's fetch was never told to bypass its own
// cached/refreshable state, so its result could be the very credential the
// CA just rejected — joining it would silently defeat the safety net. It
// waits for that flight to finish (without attaching to it, so it doesn't
// keep it alive) and then starts its own forced flight. A force=true caller
// DOES join an existing forced flight — two concurrent ForceRefresh callers
// should share one fetch, same as any other case.
func (a *Auth) acquire(ctx context.Context, out io.Writer, force bool) (string, error) {
	for {
		a.mu.Lock()
		flight := a.inflight
		if flight == nil {
			// The flight's context is deliberately detached from ctx: its
			// lifetime is governed by the set of waiters, not any single caller.
			flightCtx, cancel := context.WithCancel(context.Background())
			flight = &authFlight{
				writers: make(map[int]io.Writer),
				cancel:  cancel,
				done:    make(chan struct{}),
				forced:  force,
			}
			a.inflight = flight
			// Attach before starting the fetch so the flight cannot be
			// abandoned out from under its first waiter.
			id, _ := flight.attach(out)
			go a.runFlight(flightCtx, flight, force)
			a.mu.Unlock()
			return a.wait(ctx, flight, id)
		}
		if force && !flight.forced {
			a.mu.Unlock()
			select {
			case <-flight.done:
			case <-ctx.Done():
				return "", fmt.Errorf("authentication canceled: %w", ctx.Err())
			}
			continue
		}
		id, ok := flight.attach(out)
		a.mu.Unlock()
		if ok {
			return a.wait(ctx, flight, id)
		}

		// The flight was abandoned (its fetch is being canceled). Wait for
		// it to wind down, then start a fresh attempt.
		select {
		case <-flight.done:
		case <-ctx.Done():
			return "", fmt.Errorf("authentication canceled: %w", ctx.Err())
		}
	}
}

// wait blocks until the flight finishes or ctx is canceled, detaching the
// caller from the flight either way.
func (a *Auth) wait(ctx context.Context, flight *authFlight, id int) (string, error) {
	defer flight.detach(id)
	select {
	case <-flight.done:
		return flight.token, flight.err
	case <-ctx.Done():
		return "", fmt.Errorf("authentication canceled: %w", ctx.Err())
	}
}

// runFlight fetches a token and publishes the result to the flight.
func (a *Auth) runFlight(ctx context.Context, flight *authFlight, force bool) {
	token, err := a.fetch(ctx, flight, force)
	var expiresAt time.Time
	if err == nil {
		expiresAt, err = parseJWTExpiry(token)
	}

	a.mu.Lock()
	if err == nil {
		a.token = token
		a.expiresAt = expiresAt
	}
	a.inflight = nil
	a.mu.Unlock()

	flight.token = token
	flight.err = err
	close(flight.done)
}

// parseJWTExpiry reads the exp claim from a JWT's payload without verifying
// its signature. It is advisory only — used to schedule proactive refresh,
// never to establish trust. The policy server performs the real
// verification when the token is presented.
func parseJWTExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("malformed JWT: expected 3 dot-separated segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("failed to unmarshal JWT payload: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("JWT payload missing exp claim")
	}

	return time.Unix(claims.Exp, 0), nil
}
