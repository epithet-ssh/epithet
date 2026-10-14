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
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/directory/sqlitestore"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/test/oidctest"
	"github.com/stretchr/testify/require"
)

func TestDirectoryListingCLIWithManagedInventory(t *testing.T) {
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
			require.NoError(t, os.WriteFile(filepath.Join(dir, "static.yaml"), []byte("users:\n - id: subject:admin\n   userName: static-admin\n   groups: [{name: [wheel]}]\n"), 0600))
			name := "static-admin"
			userID := ""
			if source == "scim" {
				store, err := sqlitestore.Open(filepath.Join(dir, "state", "directory", "directory.db"))
				require.NoError(t, err)
				user, err := store.CreateUser(t.Context(), directory.ManagedUser{Metadata: directory.Metadata{ID: "subject:admin"}, ExternalID: "subject:admin", UserName: "scim-admin", Active: true}, directory.NewAuditEvent(t.Context(), "create", "subject:admin"))
				require.NoError(t, err)
				_, err = store.CreateGroup(t.Context(), directory.ManagedGroup{Metadata: directory.Metadata{ID: "group-wheel"}, DisplayName: "wheel", MemberIDs: []string{user.ID}}, directory.NewAuditEvent(t.Context(), "create", "group-wheel"))
				require.NoError(t, err)
				require.NoError(t, store.Close())
				name = "scim-admin"
				userID = user.ID
			}
			controlPath := writeControlKey(t, dir)
			config := fmt.Sprintf(`ca-key-file = "%s/ca.key"
control-key-file = %q
policy-file = "%s/policy.writ"
oidc-issuer = %q
oidc-client-id = %q
directory-mode = %q
state-dir = "%s/state"
directory-static-file = ["%s/static.yaml"]
directory-admin-group = ["wheel"]
scim-token = "provisioning-secret"
`, dir, controlPath, dir, idp.Issuer(), oidctest.ClientID, source, dir, dir)

			path := filepath.Join(dir, "server.toml")
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
			client, err := facts.NewAdminClient(endpoint, cfg)
			require.NoError(t, err)
			socket := filepath.Join(dir, "broker.sock")
			token := idp.MintIDToken("admin", time.Now().Add(time.Hour))
			b, err := broker.New(*slog.New(slog.DiscardHandler), socket, func() broker.TokenFunc {
				return func(context.Context, io.Writer, bool) (string, error) { return token, nil }
			}, ca, root.FinalURL, client, func(context.Context, string) (*broker.Identity, error) {
				return nil, fmt.Errorf("unexpected identity request")
			}, filepath.Join(dir, "agents"))
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			go b.Serve(ctx)
			<-b.Ready()
			defer b.Close()
			for _, resource := range []string{"users", "groups"} {
				for _, asJSON := range []bool{false, true} {
					args := []string{"directory", "--broker-socket", socket, resource, "list"}
					if asJSON {
						args = append(args, "--json")
					}
					output, err := exec.Command(binary, args...).CombinedOutput()
					if source == "static" {
						require.Error(t, err)
						require.Contains(t, string(output), "does not support SCIM listing")
						continue
					}
					require.NoError(t, err, string(output))
					if resource == "groups" {
						if asJSON {
							var group struct {
								ID          string `json:"id"`
								DisplayName string `json:"displayName"`
								Members     []struct {
									Value string `json:"value"`
								} `json:"members"`
							}
							require.NoError(t, json.Unmarshal(output, &group))
							require.Equal(t, "group-wheel", group.ID)
							require.Equal(t, "wheel", group.DisplayName)
							require.Len(t, group.Members, 1)
							require.Equal(t, userID, group.Members[0].Value)
						} else {
							require.Equal(t, "ID\tNAME\ngroup-wheel\twheel\n", string(output))
						}
						continue
					}
					if asJSON {
						var user map[string]any
						require.NoError(t, json.Unmarshal(output, &user))
						require.Equal(t, userID, user["id"])
						require.Equal(t, "subject:admin", user["externalId"])
						require.Equal(t, name, user["userName"])
						require.Equal(t, true, user["active"])
					} else {
						require.Equal(t, "USERNAME\tID\tEXTERNAL_ID\tACTIVE\n"+name+"\t"+userID+"\tsubject:admin\ttrue\n", string(output))
					}
				}
			}
			require.FileExists(t, filepath.Join(dir, "state", "inventory", "inventory.db"))
			if source == "static" {
				require.NoDirExists(t, filepath.Join(dir, "state", "directory"))
			}
		})
	}
}
