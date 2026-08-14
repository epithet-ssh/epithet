package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/stretchr/testify/require"
)

// newTestBroker starts a broker wired to the shared fixtures in
// broker_test.go (shortTempDir, testLogger, testCAClientOK) and tears it
// down at test end. tokenFn stands in for the auth flow; nil falls back to
// stubTokenFunc for tests that never reach auth (e.g. malformed requests).
//
// Adapted from the task brief's newTestBroker sketch: that snippet's
// TokenFunc took (ctx, out), but this codebase's real TokenFunc (see
// pkg/broker/auth.go) also carries a `force` bool, so tokenFn here matches
// the real signature instead.
func newTestBroker(t *testing.T, tokenFn TokenFunc) *Broker {
	t.Helper()
	if tokenFn == nil {
		tokenFn = stubTokenFunc
	}

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, tokenFn, testCAClientOK(t), agentSocketDir)
	require.NoError(t, err)
	b.SetShutdownTimeout(0) // Skip waiting in tests.

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		err := b.Serve(ctx)
		if err != nil && err != ctx.Err() {
			t.Errorf("broker.Serve error: %v", err)
		}
	}()
	t.Cleanup(b.Close)
	<-b.Ready()

	return b
}

// dialBroker connects to b's protocol socket.
func dialBroker(t *testing.T, b *Broker) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", b.brokerSocketPath)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestMatchStreamsOutputThenResult exercises the newline-JSON protocol's
// core streaming contract: Output events (auth progress, e.g. a device-code
// URL) must arrive before the terminal Result event. This is the JSON-wire
// replacement for gRPC's server-streaming Match RPC.
func TestMatchStreamsOutputThenResult(t *testing.T) {
	t.Parallel()
	idp := oidctest.New(t)
	tokenFn := func(ctx context.Context, out io.Writer, force bool) (string, error) {
		fmt.Fprintln(out, "visit: https://example/auth")
		return idp.MintIDToken("test@example.com", time.Now().Add(time.Hour)), nil
	}
	b := newTestBroker(t, tokenFn)
	client := dialBroker(t, b)

	require.NoError(t, json.NewEncoder(client).Encode(Request{Match: &policy.Connection{
		RemoteHost: "h", RemoteUser: "u", Hash: "abc",
	}}))

	var sawOutput bool
	sc := bufio.NewScanner(client)
	for sc.Scan() {
		var ev Event
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
		if ev.Output != "" {
			sawOutput = true
		}
		if ev.Result != nil {
			require.True(t, sawOutput, "output must precede result")
			return
		}
	}
	t.Fatal("no result event received")
}

// TestMalformedRequestGetsErrorResult verifies that a request line that
// isn't valid JSON produces a denial Result rather than hanging the client
// or closing the connection silently.
func TestMalformedRequestGetsErrorResult(t *testing.T) {
	t.Parallel()
	b := newTestBroker(t, nil)
	client := dialBroker(t, b)
	fmt.Fprintln(client, "{not json")

	sc := bufio.NewScanner(client)
	require.True(t, sc.Scan())
	var ev Event
	require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
	require.NotNil(t, ev.Result)
	require.False(t, ev.Result.Allow)
	require.NotEmpty(t, ev.Result.Error)
}

// TestMatchResultWireShapeIsLowercase pins the actual JSON emitted on the
// wire for a terminal Result event: MatchResponse must marshal as
// lowercase "allow"/"error" keys, matching what docs/architecture.md
// documents and what a third-party client (or `epithet match` itself)
// parses. Unmarshaling into the Go MatchResponse type would pass even if
// the struct had no json tags at all (Go's default field-name matching is
// case-insensitive), which is exactly the bug this test guards against -
// it inspects the raw bytes on the wire instead.
func TestMatchResultWireShapeIsLowercase(t *testing.T) {
	t.Parallel()
	b := newTestBroker(t, nil)
	client := dialBroker(t, b)
	fmt.Fprintln(client, "{not json")

	sc := bufio.NewScanner(client)
	require.True(t, sc.Scan())
	line := sc.Bytes()

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(line, &raw))
	require.Contains(t, raw, "result")

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw["result"], &result))
	require.Contains(t, result, "allow", "MatchResponse must marshal its Allow field as lowercase \"allow\"")
	require.Contains(t, result, "error", "MatchResponse must marshal its Error field as lowercase \"error\"")
	require.NotContains(t, result, "Allow", "MatchResponse must not marshal the unexported-looking capitalized field name")
	require.NotContains(t, result, "Error", "MatchResponse must not marshal the unexported-looking capitalized field name")
}

// TestClientCloseCancelsMatch ports Test_MatchStreamsUserOutput's
// close-abandons-work semantics from the old grpc_server_test.go (Task 11):
// closing the client connection before a Result arrives must cancel the
// match's context, so auth/CA work in flight is abandoned instead of
// running to completion for a client that already gave up (e.g. ssh timed
// out waiting on `epithet match`). Under gRPC this came for free from
// stream.Context(); the JSON protocol has to detect the close itself.
func TestClientCloseCancelsMatch(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	canceled := make(chan struct{})
	tokenFn := func(ctx context.Context, out io.Writer, force bool) (string, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return "", ctx.Err()
	}
	b := newTestBroker(t, tokenFn)
	client := dialBroker(t, b)

	require.NoError(t, json.NewEncoder(client).Encode(Request{Match: &policy.Connection{
		RemoteHost: "h", RemoteUser: "u", Hash: "close-test",
	}}))

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("auth never started")
	}

	require.NoError(t, client.Close())

	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("closing the client connection did not cancel the match context")
	}
}

// TestInspectReturnsInspectEvent verifies the Inspect request path returns
// exactly one Inspect event carrying the broker's InspectResponse.
func TestInspectReturnsInspectEvent(t *testing.T) {
	t.Parallel()
	b := newTestBroker(t, nil)
	client := dialBroker(t, b)

	require.NoError(t, json.NewEncoder(client).Encode(Request{Inspect: &struct{}{}}))

	sc := bufio.NewScanner(client)
	require.True(t, sc.Scan())
	var ev Event
	require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
	require.NotNil(t, ev.Inspect)
	require.Equal(t, b.brokerSocketPath, ev.Inspect.SocketPath)
}
