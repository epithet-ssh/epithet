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
	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestAgentIdentityVerifier(t *testing.T) {
	idp := oidctest.New(t)
	verify := makeAgentIdentityVerifier(wire.AuthConfig{
		Issuer: idp.Issuer(), ClientID: oidctest.ClientID,
	}, tlsconfig.Config{})
	for _, tc := range []struct {
		name      string
		overrides map[string]any
		valid     bool
	}{
		{"claims", nil, true},
		{"wrong-audience", map[string]any{"aud": "other-client"}, false},
		{"wrong-issuer", map[string]any{"iss": "https://other-issuer.example"}, false},
		{"missing-subject", map[string]any{"sub": nil}, false},
		{"missing-oid", map[string]any{"oid": nil}, true},
		{"unverified-email", map[string]any{"email_verified": false}, true},
		{"no-email", map[string]any{"email": nil, "email_verified": nil}, true},
		{"malformed-optional-claims", map[string]any{"email": 42, "email_verified": "true", "oid": []string{"id"}}, true},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel() // Exercise concurrent lazy discovery and verification.
			claims := map[string]any{"oid": "directory-id", "secret": "private-claim"}
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
			require.Equal(t, idp.Issuer(), identity.Issuer)
			require.Equal(t, oidctest.Subject("alice@example.com"), identity.Subject)
			if tc.name == "claims" {
				require.Equal(t, "directory-id", identity.OID)
				require.Equal(t, "alice@example.com", identity.Email)
				require.NotNil(t, identity.EmailVerified)
				require.True(t, *identity.EmailVerified)
			}
			if tc.name == "missing-oid" {
				require.Empty(t, identity.OID)
			}
			if tc.name == "unverified-email" {
				require.NotNil(t, identity.EmailVerified)
				require.False(t, *identity.EmailVerified)
			}
			if tc.name == "no-email" || tc.name == "malformed-optional-claims" {
				require.Empty(t, identity.Email)
				require.Nil(t, identity.EmailVerified)
			}
			encoded, err := json.Marshal(identity)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), `"id":`)
			require.NotContains(t, string(encoded), "private-claim")
			require.NotContains(t, string(encoded), token)
		})
	}
}

func TestAgentIdentityStreamsProgressSeparately(t *testing.T) {
	verified := false
	for _, tc := range []struct {
		name     string
		json     bool
		fail     bool
		verified *bool
	}{
		{name: "tab-delimited"},
		{name: "tab-delimited-unverified", verified: &verified},
		{name: "json", json: true},
		{name: "json-unverified", json: true, verified: &verified},
		{name: "failure", fail: true},
		{name: "json-failure", json: true, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
				resp := &broker.IdentityResponse{Identity: &broker.Identity{OID: "directory-id", Issuer: "issuer", Subject: "subject", Email: "alice@example.com", EmailVerified: tc.verified}}
				if tc.fail {
					resp = &broker.IdentityResponse{Error: "login failed"}
				}
				_ = enc.Encode(broker.Event{Identity: resp})
			}()
			var out, progress bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var root struct {
				Agent AgentCLI `cmd:"agent"`
			}
			parser, err := kong.New(&root)
			require.NoError(t, err)
			args := []string{"agent", "identity"}
			if tc.json {
				args = append(args, "--json")
			}
			_, err = parser.Parse(args)
			require.NoError(t, err)
			err = root.Agent.Identity.run(ctx, socket, &out, &progress)
			<-done
			require.Equal(t, "visit login URL\n", progress.String())
			if tc.fail {
				require.ErrorContains(t, err, "login failed")
				require.Empty(t, out.String())
				return
			}
			require.NoError(t, err)
			if tc.json {
				var fields map[string]any
				require.NoError(t, json.Unmarshal(out.Bytes(), &fields))
				want := map[string]any{"oid": "directory-id", "issuer": "issuer", "subject": "subject", "email": "alice@example.com"}
				if tc.verified != nil {
					want["email_verified"] = false
				}
				require.Equal(t, want, fields)
			} else {
				want := "issuer\tissuer\nsubject\tsubject\noid\tdirectory-id\nemail\talice@example.com\n"
				if tc.verified != nil {
					want += "email_verified\tfalse\n"
				}
				require.Equal(t, want, out.String())
			}
		})
	}
}
