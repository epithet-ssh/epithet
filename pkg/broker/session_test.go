package broker

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestLogoutClearsAgentsAndStartsFreshAuthentication(t *testing.T) {
	idp := oidctest.New(t)
	eval := writEvaluator(t,
		"allow userName:\"test@example.com\" -> root@*\n",
		"users:\n  - userName: test@example.com\n    id: subject:test@example.com\nhosts:\n  - pattern: \"*\"\n")
	caURL, hits := realCAAndPolicy(t, idp, eval)
	var logins atomic.Int32
	factory := func() TokenFunc {
		// Model refresh state which survives an ID token cache miss. A new
		// interactive login requires a new fetcher, not merely an empty Auth.
		var refreshState string
		return func(context.Context, io.Writer, bool) (string, error) {
			if refreshState == "" {
				logins.Add(1)
				refreshState = idp.MintIDToken("test@example.com", time.Now().Add(time.Hour))
			}
			return refreshState, nil
		}
	}
	verify := func(context.Context, string) (*Identity, error) { return &Identity{Subject: "test"}, nil }
	dir := shortTempDir(t)
	b, err := New(*testLogger(t), dir+"/b.sock", factory, testCAClient(t, caURL), caURL, testInventoryClient(t), verify, dir+"/a")
	require.NoError(t, err)
	t.Cleanup(b.Close)

	one := wire.Connection{RemoteHost: "one.example.com", RemoteUser: "root", Hash: "one"}
	two := wire.Connection{RemoteHost: "two.example.com", RemoteUser: "root", Hash: "two"}
	for _, conn := range []wire.Connection{one, two} {
		response := b.MatchWithUserOutput(t.Context(), conn, io.Discard)
		require.True(t, response.Allow, response.Error)
	}
	require.Equal(t, int32(1), logins.Load())
	require.Equal(t, int32(2), atomic.LoadInt32(hits))
	oldSession := b.session
	first, second := b.agents[one.Hash].agent, b.agents[two.Hash].agent
	oldCredential := agent.Credential{Certificate: first.Certificate()}
	conn, err := net.Dial("unix", first.AgentSocketPath())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	client := sshagent.NewClient(conn)
	_, err = client.List()
	require.NoError(t, err)

	response := b.Logout()
	require.Empty(t, response.Error)
	require.Equal(t, 2, response.AgentsCleared)
	require.Empty(t, b.agents)
	for _, a := range []*agent.Agent{first, second} {
		require.Empty(t, a.Certificate())
		require.NoFileExists(t, a.AgentSocketPath())
	}
	_, err = client.List()
	require.Error(t, err, "existing agent connections must be closed")
	// Even a CA response that arrives after cancellation cannot reinstall an
	// agent. The session check must run before credential installation.
	require.ErrorIs(t, b.ensureAgent(oldSession, one, oldCredential), context.Canceled)

	require.Empty(t, b.IdentityWithUserOutput(t.Context(), io.Discard).Error)
	require.Empty(t, b.IdentityWithUserOutput(t.Context(), io.Discard).Error)
	require.Equal(t, int32(2), logins.Load(), "login after logout must discard refresh state, then reuse its new token")
	require.Empty(t, b.agents, "authentication alone must not create a certificate agent")
	require.Equal(t, int32(2), atomic.LoadInt32(hits), "authentication alone must not contact the CA")
	match := b.MatchWithUserOutput(t.Context(), one, io.Discard)
	require.True(t, match.Allow, match.Error)
	require.Equal(t, int32(3), atomic.LoadInt32(hits))
	require.NotEqual(t, oldCredential.Certificate, b.agents[one.Hash].agent.Certificate())
}

func TestLogoutCancelsPendingLoginAndIsolatesLateResult(t *testing.T) {
	idp := oidctest.New(t)
	oldToken := idp.MintIDToken("old@example.com", time.Now().Add(time.Hour))
	newToken := idp.MintIDToken("new@example.com", time.Now().Add(time.Hour))
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var sessions int
	factory := func() TokenFunc {
		sessions++
		if sessions == 1 {
			return func(context.Context, io.Writer, bool) (string, error) {
				close(started)
				<-release // Deliberately finish successfully after cancellation.
				return oldToken, nil
			}
		}
		return func(context.Context, io.Writer, bool) (string, error) { return newToken, nil }
	}
	verify := func(_ context.Context, token string) (*Identity, error) {
		if token == newToken {
			return &Identity{Subject: "new"}, nil
		}
		return &Identity{Subject: "old"}, nil
	}
	dir := shortTempDir(t)
	b, err := New(*testLogger(t), dir+"/b.sock", factory, testCAClientOK(t), "https://ca.example", testInventoryClient(t), verify, dir+"/a")
	require.NoError(t, err)
	t.Cleanup(b.Close)
	oldSession := b.session
	done := make(chan IdentityResponse, 1)
	go func() { done <- b.IdentityWithUserOutput(t.Context(), io.Discard) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("authentication did not start")
	}
	oldSession.auth.mu.Lock()
	flightDone := oldSession.auth.inflight.done
	oldSession.auth.mu.Unlock()
	require.Empty(t, b.Logout().Error)
	select {
	case response := <-done:
		require.Contains(t, response.Error, "context canceled")
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not cancel the pending login")
	}
	response := b.IdentityWithUserOutput(t.Context(), io.Discard)
	require.Empty(t, response.Error)
	require.Equal(t, "new", response.Identity.Subject)
	release <- struct{}{}
	select {
	case <-flightDone:
	case <-time.After(5 * time.Second):
		t.Fatal("old authentication did not finish")
	}
	response = b.IdentityWithUserOutput(t.Context(), io.Discard)
	require.Empty(t, response.Error)
	require.Equal(t, "new", response.Identity.Subject)
	require.Empty(t, b.agents)
}

func TestLogoutProtocolIsIdempotentAndKeepsBrokerRunning(t *testing.T) {
	b := newTestBroker(t, nil, testIdentityVerifier)
	for range 2 {
		conn := dialBroker(t, b)
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, json.NewEncoder(conn).Encode(Request{Logout: &struct{}{}}))
		var event Event
		require.NoError(t, json.NewDecoder(conn).Decode(&event))
		require.NotNil(t, event.Logout)
		require.Empty(t, event.Logout.Error)
		require.Zero(t, event.Logout.AgentsCleared)
		require.True(t, b.Running())
	}
}

func TestLogoutDoesNotResetAnotherBroker(t *testing.T) {
	idp := oidctest.New(t)
	var calls atomic.Int32
	fetch := func(context.Context, io.Writer, bool) (string, error) {
		calls.Add(1)
		return idp.MintIDToken("test@example.com", time.Now().Add(time.Hour)), nil
	}
	verify := func(context.Context, string) (*Identity, error) { return &Identity{Subject: "test"}, nil }
	first := newTestBroker(t, fetch, verify)
	second := newTestBroker(t, fetch, verify)
	require.Empty(t, first.IdentityWithUserOutput(t.Context(), io.Discard).Error)
	require.Empty(t, second.IdentityWithUserOutput(t.Context(), io.Discard).Error)
	require.Equal(t, int32(2), calls.Load())
	require.Empty(t, first.Logout().Error)
	require.Empty(t, second.IdentityWithUserOutput(t.Context(), io.Discard).Error)
	require.Equal(t, int32(2), calls.Load())
	require.Empty(t, first.IdentityWithUserOutput(t.Context(), io.Discard).Error)
	require.Equal(t, int32(3), calls.Load())
}
