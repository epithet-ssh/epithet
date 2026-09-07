package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
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
func newTestBroker(t *testing.T, tokenFn TokenFunc, options ...Option) *Broker {
	t.Helper()
	if tokenFn == nil {
		tokenFn = stubTokenFunc
	}

	tmpDir := shortTempDir(t)
	socketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	b, err := New(*testLogger(t), socketPath, tokenFn, testCAClientOK(t), agentSocketDir, options...)
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
// core streaming contract: Output events (auth progress, e.g. the
// auth-code+PKCE URL to visit) must arrive before the terminal Result event.
// This is the JSON-wire replacement for gRPC's server-streaming Match RPC.
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
// close-abandons-work semantics from the old grpc_server_test.go, now that
// the broker speaks a newline-JSON protocol instead of gRPC: closing the
// client connection before a Result arrives must cancel the match's
// context, so auth/CA work in flight is abandoned instead of
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

func TestInspectReturnsAgentConnection(t *testing.T) {
	t.Parallel()
	b := newTestBroker(t, nil)
	conn := policy.Connection{
		RemoteHost: "server.example.com",
		RemoteUser: "deploy",
		Port:       2222,
		ProxyJump:  "bastion.example.com",
		Hash:       "connection-hash",
	}
	b.lock.Lock()
	b.agents[conn.Hash] = agentEntry{
		connection: conn,
		expiresAt:  time.Now().Add(time.Minute),
	}
	b.lock.Unlock()
	t.Cleanup(func() {
		b.lock.Lock()
		delete(b.agents, conn.Hash)
		b.lock.Unlock()
	})

	client := dialBroker(t, b)
	require.NoError(t, json.NewEncoder(client).Encode(Request{Inspect: &struct{}{}}))

	sc := bufio.NewScanner(client)
	require.True(t, sc.Scan())
	var ev Event
	require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
	require.NotNil(t, ev.Inspect)
	require.Len(t, ev.Inspect.Agents, 1)
	require.Equal(t, conn, ev.Inspect.Agents[0].Connection)
}

func TestKillReturnsTypedEventAndRemovesAgent(t *testing.T) {
	t.Parallel()
	b := newTestBroker(t, nil)
	connection := policy.Connection{RemoteHost: "server.example.com", RemoteUser: "deploy", Hash: "connection-hash"}
	b.lock.Lock()
	b.agents[connection.Hash] = agentEntry{connection: connection}
	b.lock.Unlock()

	client := dialBroker(t, b)
	require.NoError(t, json.NewEncoder(client).Encode(Request{Kill: &KillRequest{ID: connection.Hash}}))

	scanner := bufio.NewScanner(client)
	require.True(t, scanner.Scan())
	var event Event
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
	require.NotNil(t, event.Kill)
	require.Empty(t, event.Kill.Error)
	require.Equal(t, connection.Hash, event.Kill.ID)
	require.Equal(t, connection, event.Kill.Connection)

	b.lock.Lock()
	defer b.lock.Unlock()
	require.NotContains(t, b.agents, connection.Hash)
}

func TestKillUnknownAgentReturnsTypedError(t *testing.T) {
	t.Parallel()
	b := newTestBroker(t, nil)
	client := dialBroker(t, b)
	require.NoError(t, json.NewEncoder(client).Encode(Request{Kill: &KillRequest{ID: "missing"}}))

	scanner := bufio.NewScanner(client)
	require.True(t, scanner.Scan())
	var event Event
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
	require.NotNil(t, event.Kill)
	require.Equal(t, policy.ConnectionHash("missing"), event.Kill.ID)
	require.Contains(t, event.Kill.Error, "does not exist")
}

func TestIdentitySharesAgentAuthentication(t *testing.T) {
	idp := oidctest.New(t)
	token := idp.MintIDToken("test@example.com", time.Now().Add(time.Hour))
	var fetches atomic.Int32
	b := newTestBroker(t, func(ctx context.Context, out io.Writer, force bool) (string, error) {
		fetches.Add(1)
		fmt.Fprintln(out, "authenticate agent")
		return token, nil
	}, WithIdentityVerifier(func(ctx context.Context, actual string) (*Identity, error) {
		if actual != token {
			return nil, fmt.Errorf("not the agent's token")
		}
		return &Identity{OID: "directory-id", Issuer: idp.Issuer(), Subject: "login-subject"}, nil
	}))
	for i := 0; i < 2; i++ {
		conn := dialBroker(t, b)
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, json.NewEncoder(conn).Encode(Request{Identity: &struct{}{}}))
		sc := bufio.NewScanner(conn)
		var terminal *IdentityResponse
		var progress string
		for sc.Scan() {
			require.NotContains(t, sc.Text(), token, "credentials must stay inside the agent")
			var ev Event
			require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
			progress += ev.Output
			if ev.Identity != nil {
				terminal = ev.Identity
				break
			}
		}
		require.NotNil(t, terminal)
		require.Empty(t, terminal.Error)
		require.Equal(t, "directory-id", terminal.Identity.OID)
		if i == 0 {
			require.Contains(t, progress, "authenticate agent")
		} else {
			require.Empty(t, progress)
		}
		conn.Close()
	}
	result := b.MatchWithUserOutput(context.Background(), policy.Connection{RemoteHost: "h", RemoteUser: "u", Hash: "identity-reuse"}, io.Discard)
	require.False(t, result.Allow) // This fixture intentionally returns no certificate.
	require.Contains(t, result.Error, "certificate request failed")
	require.Equal(t, int32(1), fetches.Load(), "identity and SSH must share the same cached authentication")
}

func TestIdentityVerificationFailureReturnsNoIdentity(t *testing.T) {
	idp := oidctest.New(t)
	b := newTestBroker(t, testTokenFunc(t, idp), WithIdentityVerifier(func(context.Context, string) (*Identity, error) {
		return nil, fmt.Errorf("invalid issuer")
	}))
	resp := b.IdentityWithUserOutput(context.Background(), io.Discard)
	require.Nil(t, resp.Identity)
	require.Contains(t, resp.Error, "invalid issuer")
}

func TestClosingIdentityClientCancelsAuthentication(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	b := newTestBroker(t, func(ctx context.Context, out io.Writer, force bool) (string, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return "", ctx.Err()
	}, WithIdentityVerifier(func(context.Context, string) (*Identity, error) {
		t.Error("canceled authentication must not reach identity verification")
		return nil, fmt.Errorf("unexpected verification")
	}))
	conn := dialBroker(t, b)
	require.NoError(t, json.NewEncoder(conn).Encode(Request{Identity: &struct{}{}}))
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("authentication never started")
	}
	require.NoError(t, conn.Close())
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("identity disconnect did not cancel authentication")
	}
}
