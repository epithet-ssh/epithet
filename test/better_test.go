package test

import (
	"context"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
)

func Test_EndToEnd_Success(t *testing.T) {
	caPubKey, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	server, err := sshd.Start(caPubKey)
	require.NoError(t, err)
	defer server.Close()

	policyServer := startPolicyServer(caPubKey, "a")
	defer policyServer.Close()

	authority, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	caServer, err := startCAServer(authority)
	require.NoError(t, err)
	defer caServer.Close()

	caClient := caclient.New(caServer.URL)
	ag, err := agent.Create(caClient, "", "echo 'yes'")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx, ag)

	out, err := server.Ssh(ag)
	t.Log("client out:", string(out))
	require.NoError(t, err)
	require.Contains(t, out, "hello from sshd!")
}

func Test_EndToEnd_SignatureFailure(t *testing.T) {
	caPubKey, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	otherPubKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	server, err := sshd.Start(caPubKey)
	require.NoError(t, err)
	defer server.Close()

	policyServer := startPolicyServer(otherPubKey, "a")
	defer policyServer.Close()

	authority, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	caServer, err := startCAServer(authority)
	require.NoError(t, err)
	defer caServer.Close()

	caClient := caclient.New(caServer.URL)
	ag, err := agent.Create(caClient, "", "echo 'yes'")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.Run(ctx, ag)

	out, err := server.Ssh(ag)
	t.Log("client out:", string(out))
	require.Error(t, err)
	require.Contains(t, out, "Permission denied")
}

func Test_EndToEnd_DenyCertificate(t *testing.T) {
	caPubKey, caPrivKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	sshd, err := sshd.Start(caPubKey)
	require.NoError(t, err)
	defer sshd.Close()

	policy_server := startPolicyServer(caPubKey, "a")
	defer policy_server.Close()

	ca, err := ca.New(caPrivKey, policy_server.URL)
	require.NoError(t, err)

	cad, err := startCAServer(ca)
	require.NoError(t, err)
	defer cad.Close()

	cac := caclient.New(cad.URL)
	a, err := agent.Create(cac, "", "echo 'no'")
	ctx, cancel := context.WithCancel(context.Background())
	go agent.Run(ctx, a)
	require.NoError(t, err)
	defer cancel()

	out, err := sshd.Ssh(a)
	t.Log("client out:", string(out))
	require.Error(t, err)
	require.Contains(t, out, "Permission denied")
}

func Test_EndToEnd_WrongPrincipal(t *testing.T) {
	caPubKey, caPrivKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	sshd, err := sshd.Start(caPubKey)
	require.NoError(t, err)
	defer sshd.Close()

	policy_server := startPolicyServer("c")
	defer policy_server.Close()

	ca, err := ca.New(caPrivKey, policy_server.URL)
	require.NoError(t, err)

	cad, err := startCAServer(ca)
	require.NoError(t, err)
	defer cad.Close()

	cac := caclient.New(cad.URL)
	a, err := agent.Create(cac, "", "echo 'yes'")
	ctx, cancel := context.WithCancel(context.Background())
	go agent.Run(ctx, a)
	require.NoError(t, err)
	defer cancel()

	out, err := sshd.Ssh(a)
	t.Log("client out:", string(out))
	require.Error(t, err)
	require.Contains(t, out, "Permission denied")
}

func Test_EndToEnd_InvalidToken(t *testing.T) {
	caPubKey, caPrivKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	sshd, err := sshd.Start(caPubKey)
	require.NoError(t, err)
	defer sshd.Close()

	policy_server := startPolicyServer("a")
	defer policy_server.Close()

	ca, err := ca.New(caPrivKey, policy_server.URL)
	require.NoError(t, err)

	cad, err := startCAServer(ca)
	require.NoError(t, err)
	defer cad.Close()

	cac := caclient.New(cad.URL)
	a, err := agent.Create(cac, "", "echo 'whe\"ee'")
	ctx, cancel := context.WithCancel(context.Background())
	go agent.Run(ctx, a)
	require.NoError(t, err)
	defer cancel()

	out, err := sshd.Ssh(a)
	t.Log("client out:", string(out))
	require.Error(t, err)
	require.Contains(t, out, "Permission denied")
}

func startCAServer(c *ca.CA) (*httptest.Server, error) {
	handler := caserver.New(c)
	return httptest.NewServer(handler), nil
}

func startPolicyServer(caPubKey sshcert.RawPublicKey, principals ...string) *httptest.Server {
	return httptest.NewServer(policy.NewHandlerFunc(caPubKey, func(ctx context.Context, token string) (policy.Status, *ca.CertParams, error) {
		if strings.Contains(token, "yes") {
			return policy.Ok, &ca.CertParams{
				Names:      principals,
				Identity:   "tester@example.org",
				Expiration: time.Minute * 5,
			}, nil
		} else if strings.Contains(token, "no") {
			return policy.NotAuthorized, nil, nil
		} else {
			return policy.InvalidToken, nil, nil
		}
	}))
}
