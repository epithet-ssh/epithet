package agent_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestBasics(t *testing.T) {
	caPub, caPriv, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	userPub, userPriv, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	signer, err := ssh.ParsePrivateKey([]byte(caPriv))
	require.NoError(t, err)

	userCert, err := sign(signer, userPub)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	a := agent.New(testLogger(t), "")

	// Serve in background
	go func() {
		err := a.Serve(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("agent.Serve error: %v", err)
		}
	}()

	// Give agent time to start listening
	time.Sleep(10 * time.Millisecond)

	server, err := sshd.Start(caPub)
	require.NoError(t, err)
	defer server.Close()

	err = a.UseCredential(agent.Credential{
		PrivateKey:  userPriv,
		Certificate: userCert,
	})
	require.NoError(t, err)

	out, err := server.Ssh(a)
	t.Log(out)
	t.Log(server.Output.String())
	require.NoError(t, err)

	require.Contains(t, out, "hello from sshd")

	cancel()

	// Wait for agent to complete cleanup using Done() channel
	select {
	case <-a.Done():
		// Agent has been closed and cleanup is complete
	case <-time.After(1 * time.Second):
		t.Fatal("agent did not complete cleanup within timeout")
	}

	_, err = os.Stat(a.AgentSocketPath())
	if !os.IsNotExist(err) {
		t.Fatalf("auth socket not cleaned up after cancel: %s", a.AgentSocketPath())
	}
}

// TestAgentRefusesAdd confirms that a client connected to the agent's socket
// - i.e. any child process ssh spawns with SSH_AUTH_SOCK pointed here - can't
// add its own key to the keyring. Epithet's agent hands out exactly one
// broker-issued credential; accepting client-added keys would let a
// compromised child process smuggle its own identity onto the wire.
func TestAgentRefusesAdd(t *testing.T) {
	a := agent.New(testLogger(t), "")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		err := a.Serve(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("agent.Serve error: %v", err)
		}
	}()
	require.NoError(t, a.WaitReady())

	conn, err := net.Dial("unix", a.AgentSocketPath())
	require.NoError(t, err)
	defer conn.Close()

	client := sshagent.NewClient(conn)

	_, priv, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	rawKey, err := ssh.ParseRawPrivateKey([]byte(priv))
	require.NoError(t, err)

	// The SSH agent wire protocol collapses any server-side error into a
	// generic SSH_AGENT_FAILURE, so the client only ever sees "agent:
	// failure" - the "read-only" message text is asserted directly against
	// readOnlyKeyring in agent_internal_test.go. What matters here is that
	// Add is refused at all, over the real wire protocol a client actually
	// speaks.
	err = client.Add(sshagent.AddedKey{PrivateKey: rawKey})
	require.Error(t, err)
}

func sign(signer ssh.Signer, rawPubKey sshcert.RawPublicKey) (sshcert.RawCertificate, error) {
	// `ssh-keygen -s test/ca/ca -z 2 -V +15m -I brianm -n brianm,waffle ./id_ed25519.pub`
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	serial := binary.LittleEndian.Uint64(buf)

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawPubKey))
	if err != nil {
		return "", err
	}

	certificate := ssh.Certificate{
		Serial:          serial,
		Key:             pubKey,
		KeyId:           "woopdee",
		ValidPrincipals: []string{"a"},
		ValidAfter:      uint64(time.Now().Unix() - 60),
		ValidBefore:     uint64(time.Now().Unix() + 1000),
		CertType:        ssh.UserCert,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}
	err = certificate.SignCert(rand.Reader, signer)
	if err != nil {
		return "", err
	}
	rawCert := ssh.MarshalAuthorizedKey(&certificate)
	if len(rawCert) == 0 {
		return "", errors.New("unknown problem marshaling certificate")
	}
	return sshcert.RawCertificate(string(rawCert)), nil
}

func testLogger(t *testing.T) *slog.Logger {
	return slog.New(tint.NewHandler(t.Output(), &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "15:04:05",
	}))
}
