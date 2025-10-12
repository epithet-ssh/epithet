package agent_test

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
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

	a, err := agent.Start(t.Context(), nil, "")
	require.NoError(t, err)

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

	a.Close()
	_, err = os.Stat(a.AgentSocketPath())
	if !os.IsNotExist(err) {
		t.Fatalf("auth socket not cleaned up after cancel: %s", a.AgentSocketPath())
	}
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
