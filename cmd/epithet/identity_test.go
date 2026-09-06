package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestAgentIdentityUsesProfileAndSocketOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("agent:\n  name: work\n  ca-url: https://ca.example\n"), 0600))
	for _, args := range [][]string{{"agent", "identity"}, {"agent", "--name", "personal", "identity", "--broker", "/tmp/identity.sock"}} {
		var root struct {
			Agent AgentCLI `cmd:"agent"`
		}
		parser, err := kong.New(&root, kong.Configuration(kongyaml.Loader, path))
		require.NoError(t, err)
		_, err = parser.Parse(args)
		require.NoError(t, err)
		socket, err := resolveAgentBrokerSocket(&root.Agent, root.Agent.Identity.Broker)
		require.NoError(t, err)
		if len(args) == 2 {
			home, err := os.UserHomeDir()
			require.NoError(t, err)
			require.Equal(t, filepath.Join(home, ".epithet/run/work/broker.sock"), socket)
		} else {
			require.Equal(t, "/tmp/identity.sock", socket)
		}
	}
}

func TestAgentIdentityVerifier(t *testing.T) {
	idp := oidctest.New(t)
	verify := makeAgentIdentityVerifier(wire.AuthConfig{
		Issuer: idp.Issuer(), ClientID: oidctest.ClientID, UserIDClaim: "oid",
	}, tlsconfig.Config{})
	for _, tc := range []struct {
		name      string
		overrides map[string]any
		valid     bool
	}{
		{"mapped", nil, true},
		{"wrong-audience", map[string]any{"aud": "other-client"}, false},
		{"wrong-issuer", map[string]any{"iss": "https://other-issuer.example"}, false},
		{"missing-subject", map[string]any{"sub": nil}, false},
		{"missing-id", map[string]any{"oid": nil}, false},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel() // Exercise concurrent lazy discovery and verification.
			claims := map[string]any{"oid": "directory-id"}
			for k, v := range tc.overrides {
				claims[k] = v
			}
			token := idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), claims)
			identity, err := verify(context.Background(), token)
			if !tc.valid {
				require.Error(t, err)
				require.Nil(t, identity)
				require.NotContains(t, err.Error(), token)
				return
			}
			require.NoError(t, err)
			require.Equal(t, &broker.Identity{ID: "directory-id", Issuer: idp.Issuer(), Subject: oidctest.Subject("alice@example.com")}, identity)
		})
	}
}

func TestAgentIdentityStreamsProgressSeparately(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "epithet-id-")
			require.NoError(t, err)
			t.Cleanup(func() { os.RemoveAll(dir) })
			socket := filepath.Join(dir, "b.sock")
			listener, err := net.Listen("unix", socket)
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				var req broker.Request
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				if req.Identity == nil {
					t.Error("expected identity request")
					return
				}
				enc := json.NewEncoder(conn)
				_ = enc.Encode(broker.Event{Output: "visit login URL\n"})
				resp := &broker.IdentityResponse{Identity: &broker.Identity{ID: "directory-id", Issuer: "issuer", Subject: "subject"}}
				if fail {
					resp = &broker.IdentityResponse{Error: "login failed"}
				}
				_ = enc.Encode(broker.Event{Identity: resp})
			}()
			var out, progress bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = (&AgentIdentityCLI{}).run(ctx, socket, &out, &progress)
			<-done
			require.Equal(t, "visit login URL\n", progress.String())
			if fail {
				require.ErrorContains(t, err, "login failed")
				require.Empty(t, out.String())
				return
			}
			require.NoError(t, err)
			var fields map[string]string
			require.NoError(t, json.Unmarshal(out.Bytes(), &fields))
			require.Equal(t, map[string]string{"id": "directory-id", "issuer": "issuer", "subject": "subject"}, fields)
		})
	}
}

func TestPolicyUserIDClaimConfigAndCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("policy:\n  oidc:\n    issuer: https://issuer.example\n    user-id-claim: directory_id\n"), 0600))
	for _, override := range []bool{false, true} {
		var root struct {
			Policy PolicyServerCLI `cmd:"policy"`
		}
		parser, err := kong.New(&root, kong.Configuration(kongyaml.Loader, path))
		require.NoError(t, err)
		args := []string{"policy"}
		want := "directory_id"
		if override {
			args = append(args, "--oidc-user-id-claim", "oid")
			want = "oid"
		}
		_, err = parser.Parse(args)
		require.NoError(t, err)
		require.Equal(t, want, root.Policy.OIDC.UserIDClaim)
	}
}
