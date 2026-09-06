package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/stretchr/testify/require"
)

func TestIdentityCAConfigPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		defaults []string
		explicit string
		args     []string
		want     []string
	}{
		{"default-client-config", []string{"agent:\n  ca-url: https://default.example\n"}, "", nil, []string{"https://default.example"}},
		{"explicit-client-config", nil, "agent:\n  ca-url: https://explicit.example\n", nil, []string{"https://explicit.example"}},
		{"multiple-CAs", nil, "agent:\n  ca-url: [https://one.example, 'priority=50:https://two.example']\n", nil, []string{"https://one.example", "priority=50:https://two.example"}},
		{"later-default-file", []string{"agent:\n  ca-url: https://first.example\n", "agent:\n  ca-url: https://last.example\n"}, "", nil, []string{"https://last.example"}},
		{"explicit-over-default", []string{"agent:\n  ca-url: https://default.example\n"}, "agent:\n  ca-url: https://explicit.example\n", nil, []string{"https://explicit.example"}},
		{"unrelated-overlay-retains-default", []string{"agent:\n  ca-url: https://default.example\n"}, "agent:\n  name: work\n", nil, []string{"https://default.example"}},
		{"identity-config-over-agent", nil, "agent:\n  ca-url: https://agent.example\nidentity:\n  ca-url: https://identity.example\n", nil, []string{"https://identity.example"}},
		{"CLI-over-both-config-sections", nil, "agent:\n  ca-url: https://agent.example\nidentity:\n  ca-url: https://identity.example\n", []string{"--ca-url", "https://cli.example"}, []string{"https://cli.example"}},
		{"repeated-CLI-URLs", nil, "agent:\n  ca-url: https://agent.example\n", []string{"--ca-url", "https://one.example", "--ca-url", "https://two.example"}, []string{"https://one.example", "https://two.example"}},
		{"no-config", nil, "", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write := func(body string) string {
				path := filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(body), 0600))
				return path
			}
			var paths []string
			for _, body := range tc.defaults {
				paths = append(paths, write(body))
			}
			var root struct {
				Config   kong.ConfigFlag `name:"config"`
				Identity IdentityCLI     `cmd:"identity"`
			}
			parser, err := kong.New(&root, kong.Configuration(kongyaml.Loader, paths...))
			require.NoError(t, err)
			args := []string{"identity"}
			if tc.explicit != "" {
				args = append([]string{"--config", write(tc.explicit)}, args...)
			}
			_, err = parser.Parse(append(args, tc.args...))
			require.NoError(t, err)
			urls, err := root.Identity.resolveCAURLs(paths, string(root.Config))
			if tc.want == nil {
				require.ErrorContains(t, err, "set agent.ca-url")
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, urls)
			}
		})
	}
}

func TestIdentityOutputRequiresVerifiedTokenAndContainsNoCredentials(t *testing.T) {
	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(context.Background(), oidc.Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID})
	require.NoError(t, err)
	for _, tc := range []struct {
		name      string
		overrides map[string]any
		valid     bool
	}{
		{"valid", nil, true},
		{"wrong-audience", map[string]any{"aud": "other-client"}, false},
		{"wrong-issuer", map[string]any{"iss": "https://other-issuer.example"}, false},
		{"missing-subject", map[string]any{"sub": nil}, false},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := idp.MintIDTokenWithClaims("alice@example.com", time.Now().Add(time.Minute), tc.overrides)
			var out bytes.Buffer
			err := writeVerifiedIdentity(context.Background(), validator, token, &out)
			if !tc.valid {
				require.Error(t, err)
				require.Empty(t, out.String())
				return
			}
			require.NoError(t, err)
			var fields map[string]string
			require.NoError(t, json.Unmarshal(out.Bytes(), &fields))
			require.Equal(t, map[string]string{"issuer": idp.Issuer(), "subject": oidctest.Subject("alice@example.com")}, fields)
			require.NotContains(t, out.String(), token)
		})
	}
}
