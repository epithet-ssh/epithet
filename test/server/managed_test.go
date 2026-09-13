package server_test

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestManagedCombinedEnrollmentAdminCLIAndIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dir := shortTempDir(t)
	idp := oidctest.New(t)
	binary := filepath.Join(dir, "epithet")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/epithet")
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))
	_, private, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), []byte(private), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "static.yaml"), []byte("users:\n - id: subject:admin\n   userName: admin\n   groups: [operators]\nhosts:\n - pattern: '*'\n   accounts: [root]\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.writ"), []byte("allow userName:admin -> root@*\n"), 0600))
	config := fmt.Sprintf(`server:
  ca-key: %s/ca.key
policy:
  policy-file: %s/policy.writ
inventory:
  static: [%s/static.yaml]
  state-dir: %s/state
  admin-group: [operators]
  oidc:
    issuer: %s
    client-id: %s
`, dir, dir, dir, dir, idp.Issuer(), oidctest.ClientID)
	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0600))
	port := availablePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d/", port)
	process := exec.Command(binary, "--config", configPath, "--insecure", "server", "--listen", fmt.Sprintf("127.0.0.1:%d", port))
	process.Env = append(os.Environ(), "TMPDIR="+dir)
	process.Stdout = os.Stderr
	process.Stderr = os.Stderr
	require.NoError(t, process.Start())
	t.Cleanup(func() { process.Process.Signal(syscall.SIGTERM); process.Wait() })
	waitForTCP(t, fmt.Sprintf("127.0.0.1:%d", port), 15*time.Second)
	// All services are private Unix listeners; the router owns the TCP port.
	sockets, err := filepath.Glob(filepath.Join(dir, "epithet-server-*", "*.sock"))
	require.NoError(t, err)
	var names []string
	for _, socket := range sockets {
		names = append(names, filepath.Base(socket))
	}
	require.ElementsMatch(t, []string{"ca.sock", "inventory.sock", "policy.sock"}, names)
	// Exercise the Caddy-style topology: external HTTPS termination forwards
	// plain HTTP to the router. Clients trust only the external TLS certificate.
	upstream, err := url.Parse(base)
	require.NoError(t, err)
	front := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(upstream))
	t.Cleanup(front.Close)
	base = front.URL + "/"
	trust := filepath.Join(dir, "tls-ca.pem")
	require.NoError(t, os.WriteFile(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0600))
	tlsCfg := tlsconfig.Config{CACertFile: trust}
	inventoryClient, err := inventoryclient.New(tlsCfg)
	require.NoError(t, err)
	client, err := caclient.New([]caclient.CAEndpoint{{URL: base}}, caclient.WithTLSConfig(tlsCfg))
	require.NoError(t, err)
	root, err := client.GetRoot(t.Context())
	require.NoError(t, err)
	endpoint, err := caclient.InventoryURL(root, tlsCfg)
	require.NoError(t, err)
	require.Equal(t, base+"inventory", endpoint)
	_, status, err := inventoryClient.Control(t.Context(), endpoint, "", inventoryapi.ControlRequest{Action: "list"})
	require.Error(t, err)
	require.Equal(t, http.StatusUnauthorized, status, "the router must leave admin authentication to inventory")
	proposal := inventory.Proposal{Names: []string{"managed.example"}, Accounts: []string{"root"}, PrincipalMode: inventory.AccountNamePrincipals}
	enrolled, status, err := inventoryClient.Control(t.Context(), endpoint, "", inventoryapi.ControlRequest{Action: "enroll", Host: &proposal})
	require.NoError(t, err)
	require.Equal(t, 202, status)
	token := idp.MintIDToken("admin", time.Now().Add(time.Hour))
	pub, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	request := caserver.CreateCertRequest{PublicKey: pub, Connection: policy.Connection{RemoteHost: "managed.example", RemoteUser: "root", Port: 22}}
	_, err = client.GetCert(t.Context(), token, &request)
	require.Error(t, err, "pending must block wildcard-based issuance")
	// Run the real admin CLI through the broker's Unix socket and existing login.
	socket := filepath.Join(dir, "broker.sock")
	b, err := broker.New(*slog.New(slog.NewTextHandler(io.Discard, nil)), socket, func(context.Context, io.Writer, bool) (string, error) { return token, nil }, client, filepath.Join(dir, "agents"), broker.WithInventoryClient(inventoryClient))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go b.Serve(ctx)
	<-b.Ready()
	defer b.Close()
	admin := func(args ...string) []byte {
		cmd := exec.Command(binary, append([]string{"inventory", "--broker", socket}, args...)...)
		cmd.Stdin = strings.NewReader("approve\n")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return out
	}
	listing := admin("list", "--pending")
	require.Contains(t, string(listing), enrolled.Host.ID)
	require.NotContains(t, string(listing), token)
	approved := admin("approve", enrolled.Host.ID)
	require.Contains(t, string(approved), "approved")
	cert, err := client.GetCert(t.Context(), token, &request)
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)
	created := strings.TrimSpace(string(admin("token", "create", "--quiet")))
	require.Len(t, created, 64)
	proposal.Names = []string{"second.example"}
	second, status, err := inventoryClient.Control(t.Context(), endpoint, "", inventoryapi.ControlRequest{Action: "enroll", Host: &proposal, Token: created})
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Equal(t, "approved", second.Host.Status)
	require.Equal(t, created, second.Host.ID, "the enrollment token reserves the eventual host ID")
	admin("remove", enrolled.Host.ID)
	_, err = client.GetCert(t.Context(), token, &request)
	require.Error(t, err, "removal must block new issuance through wildcard")
	inspection := admin("show", enrolled.Host.ID)
	require.Contains(t, string(inspection), "removed")
}
