package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	rpc "github.com/epithet-ssh/epithet/internal/agent"
	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
)

func Test_EndToEnd_Success(t *testing.T) {
	caPubKey, caPrivKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	sshd, err := sshd.Start(caPubKey)
	require.NoError(t, err)
	defer sshd.Close()

	policy_server := startPolicyServer("a")
	defer policy_server.Close()

	ca, err := ca.New(caPrivKey, policy_server.URL)
	require.NoError(t, err)

	ca_server, err := startCAServer(ca)
	require.NoError(t, err)
	defer ca_server.Close()

	ca_client := caclient.New(ca_server.URL)
	agent, err := agent.Start(ca_client)
	require.NoError(t, err)
	defer agent.Close()

	authn_client, err := rpc.NewClient(agent.ControlSocketPath())
	require.NoError(t, err)
	_, err = authn_client.Authenticate(context.Background(), &rpc.AuthnRequest{
		Token: "This token is ignored by our policy server",
	})
	require.NoError(t, err)

	out, err := sshd.Ssh(agent)
	require.NoError(t, err)
	require.Contains(t, out, "hello from sshd")
}

func Test_EndToEnd_Failure(t *testing.T) {
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
	a, err := agent.Start(cac)
	require.NoError(t, err)
	defer a.Close()

	authnClient, err := rpc.NewClient(a.ControlSocketPath())
	require.NoError(t, err)
	_, err = authnClient.Authenticate(context.Background(), &rpc.AuthnRequest{
		Token: "yes, please!",
	})
	require.NoError(t, err)

	out, err := sshd.Ssh(a)
	require.Error(t, err)
	require.Contains(t, out, "Permission denied")
}

func startCAServer(c *ca.CA) (*httptest.Server, error) {
	handler := caserver.New(c)
	return httptest.NewServer(handler), nil
}

func startPolicyServer(principals ...string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, err := json.Marshal(&ca.CertParams{
			Names:      principals,
			Identity:   "tester@example.org",
			Expiration: time.Minute * 5,
		})
		if err != nil {
			w.Header().Add("Content-type", "text/plain")

			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Add("Content-type", "application/json")
		w.WriteHeader(200)
		w.Write(out)
	}))
}
