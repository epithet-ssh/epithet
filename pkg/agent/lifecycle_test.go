package agent_test

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func testCredential(t *testing.T) agent.Credential {
	t.Helper()
	pub, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	require.NoError(t, err)
	cert, err := sign(signer, pub)
	require.NoError(t, err)
	return agent.Credential{PrivateKey: priv, Certificate: cert}
}

func TestStartReturnsReadyAgent(t *testing.T) {
	credential := testCredential(t)
	a, err := agent.Start(testLogger(t), "", credential)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	require.True(t, a.Running())
	info, err := os.Stat(a.AgentSocketPath())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	conn, err := net.Dial("unix", a.AgentSocketPath())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	client := sshagent.NewClient(conn)
	keys, err := client.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	cert, err := sshcert.Parse(credential.Certificate)
	require.NoError(t, err)
	require.Equal(t, cert.Marshal(), keys[0].Blob)
	data := []byte("ready immediately after Start")
	signature, err := client.Sign(cert, data)
	require.NoError(t, err)
	require.NoError(t, cert.Key.Verify(data, signature))
}

func TestStartFailureLeavesNoSocket(t *testing.T) {
	valid := testCredential(t)
	for _, tc := range []struct {
		name       string
		credential agent.Credential
	}{
		{"invalid certificate", agent.Credential{PrivateKey: valid.PrivateKey}},
		{"invalid private key", agent.Credential{Certificate: valid.Certificate}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.sock")
			a, err := agent.Start(testLogger(t), path, tc.credential)
			require.Error(t, err)
			require.Nil(t, a)
			_, err = os.Stat(path)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
	t.Run("listener failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "agent.sock")
		a, err := agent.Start(testLogger(t), path, valid)
		require.ErrorContains(t, err, "unable to listen")
		require.Nil(t, a)
		_, err = os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestCredentialReplacementPreservesLiveConnection(t *testing.T) {
	initial, replacement := testCredential(t), testCredential(t)
	a, err := agent.Start(testLogger(t), "", initial)
	require.NoError(t, err)
	t.Cleanup(a.Close)
	conn, err := net.Dial("unix", a.AgentSocketPath())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	client := sshagent.NewClient(conn)

	require.Error(t, a.UseCredential(agent.Credential{Certificate: replacement.Certificate}))
	require.Equal(t, initial.Certificate, a.Certificate())
	keys, err := client.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	cert, err := sshcert.Parse(initial.Certificate)
	require.NoError(t, err)
	require.Equal(t, cert.Marshal(), keys[0].Blob)

	require.NoError(t, a.UseCredential(replacement))
	keys, err = client.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	cert, err = sshcert.Parse(replacement.Certificate)
	require.NoError(t, err)
	require.Equal(t, cert.Marshal(), keys[0].Blob)
	signature, err := client.Sign(cert, []byte("replacement"))
	require.NoError(t, err)
	require.NoError(t, cert.Key.Verify([]byte("replacement"), signature))
}

func TestCloseFinishesWithIdleAndPartialRequestConnections(t *testing.T) {
	a, err := agent.Start(testLogger(t), "", testCredential(t))
	require.NoError(t, err)
	t.Cleanup(a.Close)
	var connections []net.Conn
	for _, partial := range []bool{false, true} {
		conn, err := net.Dial("unix", a.AgentSocketPath())
		require.NoError(t, err)
		defer conn.Close()
		connections = append(connections, conn)
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		// A completed request proves this connection is being served before
		// leaving it idle or waiting for the rest of an incomplete frame.
		_, err = sshagent.NewClient(conn).List()
		require.NoError(t, err)
		if partial {
			_, err = conn.Write([]byte{0, 0})
			require.NoError(t, err)
		}
	}
	closed := make(chan struct{})
	go func() {
		a.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish with connected clients")
	}
	select {
	case <-a.Done():
	default:
		t.Fatal("Close returned before cleanup completed")
	}
	require.False(t, a.Running())
	require.Empty(t, a.Certificate())
	for _, conn := range connections {
		_, err := conn.Read(make([]byte, 1))
		require.Error(t, err)
		if err, ok := err.(net.Error); ok {
			require.False(t, err.Timeout(), "Close must close the connection, not leave it idle")
		}
	}
	_, err = os.Stat(a.AgentSocketPath())
	require.ErrorIs(t, err, os.ErrNotExist)
	a.Close()
}

func TestConcurrentCloseAndReplacement(t *testing.T) {
	credential := testCredential(t)
	for range 20 {
		a, err := agent.Start(testLogger(t), "", credential)
		require.NoError(t, err)
		start := make(chan struct{})
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				<-start
				for range 10 {
					// Either replacement wins or shutdown rejects it.
					if err := a.UseCredential(credential); err != nil {
						if err.Error() != "agent has been stopped" {
							t.Errorf("unexpected replacement error: %v", err)
						}
						return
					}
				}
			})
		}
		for range 2 {
			workers.Go(func() {
				<-start
				a.Close()
				select {
				case <-a.Done():
				default:
					t.Error("concurrent Close returned before cleanup completed")
				}
			})
		}
		close(start)
		workers.Wait()
		require.Empty(t, a.Certificate(), "replacement must not restore a closed agent's credential")
		require.ErrorContains(t, a.UseCredential(credential), "stopped")
	}
}
