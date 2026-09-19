package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestDirectoryUsersCLIWithStaticHosts(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	binary := filepath.Join(shortTempDir(t), "epithet")
	out, err := exec.Command("go", "build", "-o", binary, "../../cmd/epithet").CombinedOutput()
	require.NoError(t, err, string(out))
	for _, source := range []string{"static", "scim"} {
		t.Run(source, func(t *testing.T) {
			dir := shortTempDir(t)
			idp := oidctest.New(t)
			_, key, err := sshcert.GenerateKeys()
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), []byte(key), 0600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.writ"), []byte("allow group:wheel -> root@*\n"), 0600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "static.yaml"), []byte("users:\n - id: subject:admin\n   userName: static-admin\n   groups: [wheel]\n"), 0600))
			name := "static-admin"
			if source == "scim" {
				store, err := sqlitestore.Open(filepath.Join(dir, "state", "directory", "directory.db"))
				require.NoError(t, err)
				user, err := store.CreateUser(t.Context(), directory.ManagedUser{ExternalID: "subject:admin", UserName: "scim-admin", Active: true})
				require.NoError(t, err)
				_, err = store.CreateGroup(t.Context(), directory.Group{DisplayName: "wheel", MemberIDs: []string{user.ID}})
				require.NoError(t, err)
				require.NoError(t, store.Close())
				name = "scim-admin"
			}
			config := fmt.Sprintf(`server:
  ca-key: %s/ca.key
policy:
  policy-file: %s/policy.writ
inventory:
  inventory-source: static
  directory-source: %s
  scim-token: provisioning-secret
  state-dir: %s/state
  static: [%s/static.yaml]
  admin-group: [wheel]
  oidc:
    issuer: %s
    client-id: %s
`, dir, dir, source, dir, dir, idp.Issuer(), oidctest.ClientID)
			path := filepath.Join(dir, "server.yaml")
			require.NoError(t, os.WriteFile(path, []byte(config), 0600))
			address := fmt.Sprintf("127.0.0.1:%d", availablePort(t))
			process := exec.Command(binary, "--config", path, "--insecure", "server", "--listen", address)
			process.Env = append(os.Environ(), "TMPDIR="+dir)
			process.Stdout, process.Stderr = os.Stderr, os.Stderr
			require.NoError(t, process.Start())
			t.Cleanup(func() { process.Process.Signal(syscall.SIGTERM); process.Wait() })
			waitForTCP(t, address, 15*time.Second)
			cfg := tlsconfig.Config{Insecure: true}
			ca, err := caclient.New([]caclient.CAEndpoint{{URL: "http://" + address + "/"}}, caclient.WithTLSConfig(cfg))
			require.NoError(t, err)
			root, err := ca.GetRoot(t.Context())
			require.NoError(t, err)
			endpoint, err := caclient.InventoryURL(root, cfg)
			require.NoError(t, err)
			require.Equal(t, "http://"+address+"/inventory", endpoint)
			client, err := inventoryclient.New(endpoint, cfg)
			require.NoError(t, err)
			socket := filepath.Join(dir, "broker.sock")
			token := idp.MintIDToken("admin", time.Now().Add(time.Hour))
			b, err := broker.New(*slog.New(slog.DiscardHandler), socket, func(context.Context, io.Writer, bool) (string, error) { return token, nil }, ca, root.FinalURL, client, func(context.Context, string) (*broker.Identity, error) {
				return nil, fmt.Errorf("unexpected identity request")
			}, filepath.Join(dir, "agents"))
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			go b.Serve(ctx)
			<-b.Ready()
			defer b.Close()
			for _, asJSON := range []bool{false, true} {
				args := []string{"directory", "--broker", socket, "users", "list"}
				if asJSON {
					args = append(args, "--json")
				}
				output, err := exec.Command(binary, args...).CombinedOutput()
				require.NoError(t, err, string(output))
				if asJSON {
					var snapshot inventoryapi.UserSnapshot
					require.NoError(t, json.Unmarshal(output, &snapshot))
					require.NotEmpty(t, snapshot.Revision)
					require.Equal(t, []inventoryapi.DirectoryUser{{UserName: name, ID: "subject:admin", Active: true, Groups: []string{"wheel"}}}, snapshot.Users)
				} else {
					require.Equal(t, "USERNAME\tID\tACTIVE\tGROUPS\n"+name+"\tsubject:admin\ttrue\twheel\n", string(output))
				}
			}
			require.NoDirExists(t, filepath.Join(dir, "state", "inventory"))
			if source == "static" {
				require.NoDirExists(t, filepath.Join(dir, "state"))
			}
		})
	}
}
