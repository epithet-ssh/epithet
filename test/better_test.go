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

func Test_EndToEnd2(t *testing.T) {
	caPubKey, caPrivKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	sshd, err := sshd.Start(caPubKey)
	require.NoError(t, err)
	defer sshd.Close()

	policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-type", "application/json")
		w.WriteHeader(200)
		out, err := json.Marshal(&ca.CertParams{
			Names:      []string{"a"},
			Identity:   "tester@example.org",
			Expiration: time.Minute * 5,
		})
		require.NoError(t, err)
		w.Write(out)
	}))
	defer policyServer.Close()

	ca, err := ca.New(caPrivKey, policyServer.URL)
	require.NoError(t, err)

	cad, err := startCAServer(ca)
	require.NoError(t, err)
	defer cad.Close()

	cac := caclient.New(cad.srv.URL)
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
	require.NoError(t, err)
	require.Contains(t, out, "hello from sshd")
}

type caServer struct {
	c   *ca.CA
	srv *httptest.Server
}

func startCAServer(c *ca.CA) (*caServer, error) {
	handler := caserver.New(c)
	srv := httptest.NewServer(handler)

	cas := caServer{
		c:   c,
		srv: srv,
	}

	return &cas, nil
}

func (c *caServer) Close() {
	c.srv.Close()
}
