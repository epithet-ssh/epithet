package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEditorCancelAndValidationRetry(t *testing.T) {
	t.Setenv("EDITOR", `sh -c ': > "$1"' editor`)
	initial := inventory.Proposal{Names: []string{"one"}, Labels: map[string]string{}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
	_, err := editProposal(initial, bufio.NewReader(strings.NewReader("")))
	require.ErrorIs(t, err, errCanceled)
	t.Setenv("EDITOR", "true")
	p, err := editProposal(initial, bufio.NewReader(strings.NewReader("")))
	require.NoError(t, err)
	require.Equal(t, initial, p)
	script := filepath.Join(t.TempDir(), "editor")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nif [ ! -f \"$1.once\" ]; then\n touch \"$1.once\"\n printf 'invalid: yaml\\n' > \"$1\"\nelse\n rm \"$1.once\"\n printf 'names: [fixed]\\naccounts: []\\nprincipal-mode: account-name\\n' > \"$1\"\nfi\n"), 0700))
	t.Setenv("EDITOR", script)
	p, err = editProposal(initial, bufio.NewReader(strings.NewReader("edit\n")))
	require.NoError(t, err)
	require.Equal(t, []string{"fixed"}, p.Names)
}
func TestManagedEnrollmentLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, token, status    string
		rejected, localFailure bool
	}{
		{name: "pending", status: "pending"},
		{name: "token admission", token: "one-use-token", status: "approved"},
		{name: "rejection then rerun", status: "pending", rejected: true},
		{name: "local failure", localFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, local, env, runner, main, fragment := newSSHDConfigurationTest(t)
			cmd.DomainFile, cmd.CAPubkeyFile = local.DomainFile, local.CAPubkeyFile
			cmd.Names = []string{"one.example"}
			cmd.Token = tc.token
			cmd.sshdEnv = env
			cmd.EpithetBinary = ""
			resolutions := 0
			env.executable = func() (string, error) {
				resolutions++
				return "/test/epithet", nil
			}
			if tc.localFailure {
				runner.run = func(_ int, _ string, _ []string) ([]byte, error) {
					return nil, errors.New("local validation failed")
				}
			}
			reviewFile := filepath.Join(t.TempDir(), "reviewed.yaml")
			t.Setenv("REVIEW", reviewFile)
			t.Setenv("DOMAIN", cmd.DomainFile)
			t.Setenv("CA_KEY", cmd.CAPubkeyFile)
			t.Setenv("FRAGMENT", fragment)
			// The first review sees no installed state. Capture the actual proposal
			// so the test can compare its in-memory domain with the installed one.
			t.Setenv("EDITOR", `sh -c 'if [ ! -e "$REVIEW" ]; then test ! -e "$DOMAIN" && test ! -e "$CA_KEY" && test ! -e "$FRAGMENT" || exit 9; fi; cp "$1" "$REVIEW"' editor`)
			pub := newTestCAPublicKey(t)
			requests := make(chan inventoryapi.ControlRequest, 2)
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Link", `<manage>; rel="https://epithet.dev/rel/inventory"`)
				fmt.Fprint(w, pub)
			})
			mux.HandleFunc("/manage", func(w http.ResponseWriter, r *http.Request) {
				var req inventoryapi.ControlRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				requests <- req
				require.FileExists(t, fragment, "local sshd configuration precedes submission")
				domain, err := principal.ReadDomainFile(cmd.DomainFile)
				require.NoError(t, err)
				require.Equal(t, string(domain), req.Host.Domain)
				if tc.rejected {
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(inventoryapi.ControlResponse{Error: "rejected"})
					return
				}
				json.NewEncoder(w).Encode(inventoryapi.ControlResponse{Host: &inventory.HostRecord{ID: "record", Status: tc.status}})
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			cmd.CAURL = server.URL + "/"
			first, err := cmd.enroll(t.Context(), nil, tlsconfig.Config{Insecure: true})
			require.Equal(t, 1, resolutions, "settings are resolved once per invocation")
			if tc.localFailure {
				require.ErrorContains(t, err, "local validation failed")
				require.Empty(t, requests, "failed local setup must not submit")
				requireFileContents(t, main, "Port 22\n")
				return
			}
			if tc.rejected {
				require.ErrorContains(t, err, "local sshd is configured, but registration did not complete")
				require.Nil(t, first)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.status, first.Status)
			}
			require.Len(t, runner.calls, 4)
			req := <-requests
			data, err := os.ReadFile(reviewFile)
			require.NoError(t, err)
			var reviewed inventory.Proposal
			require.NoError(t, yaml.Unmarshal(data, &reviewed))
			require.Equal(t, reviewed, *req.Host)
			require.Equal(t, tc.token, req.Token)
			requireFileContents(t, cmd.CAPubkeyFile, string(pub))
			// A rerun reviews and submits anew, reusing local identity and skipping
			// reload when sshd is already configured. No prior record is resumed.
			tc.rejected = false
			cmd.Token = ""
			tc.status = "pending"
			second, err := cmd.enroll(t.Context(), nil, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			require.Equal(t, "pending", second.Status)
			require.Equal(t, 2, resolutions)
			require.Len(t, runner.calls, 5, "unchanged setup only validates on rerun")
			require.False(t, second.DomainCreated)
			require.False(t, second.CAPublicKeyCreated)
			require.Equal(t, reviewed.Domain, string(second.Domain))
			resubmitted := <-requests
			require.Equal(t, reviewed, *resubmitted.Host)
			require.Empty(t, resubmitted.Token)
			require.NoFileExists(t, filepath.Join(filepath.Dir(cmd.DomainFile), "enrollment.key"))
		})
	}
}
func TestEnrollmentCancelLeavesPersistentStateUnchanged(t *testing.T) {
	t.Setenv("EDITOR", `sh -c ': > "$1"' editor`)
	cmd, enrollment, env, runner, main, fragment := newSSHDConfigurationTest(t)
	pub := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<manage>; rel="https://epithet.dev/rel/inventory"`)
		fmt.Fprint(w, pub)
	}))
	defer server.Close()
	cmd.CAURL = server.URL + "/"
	cmd.DomainFile = enrollment.DomainFile
	cmd.CAPubkeyFile = enrollment.CAPubkeyFile
	cmd.sshdEnv = env
	input, err := os.CreateTemp(t.TempDir(), "input")
	require.NoError(t, err)
	defer input.Close()
	old := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = old }()
	_, err = cmd.enroll(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.ErrorIs(t, err, errCanceled)
	require.Empty(t, runner.calls)
	require.NoDirExists(t, filepath.Dir(cmd.DomainFile))
	require.NoFileExists(t, cmd.CAPubkeyFile)
	requireFileContents(t, main, "Port 22\n")
	_, err = os.Stat(fragment)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestProposedHostNamesUseConfiguredSearchSuffix(t *testing.T) {
	for _, tc := range []struct {
		name, domain string
		want         []string
	}{
		{"", "example.com", []string{}},
		{"host", "", []string{"host"}},
		{"HOST", "Example.COM.", []string{"host.example.com"}},
		{"HOST.Example.COM.", "example.com", []string{"host.example.com"}},
		{"host.notexample.com", "example.com", []string{"host.notexample.com.example.com"}},
	} {
		require.Equal(t, tc.want, proposedHostNames(tc.name, tc.domain))
	}
	for _, tc := range []struct{ config, want string }{
		{"nameserver 127.0.0.1\n", ""},
		{"# search ignored\nsearch home.example another.example # comment\n", "home.example"},
		{"domain home.example\n", "home.example"},
		{"domain old.example\nsearch new.example other.example\n", "new.example"},
	} {
		require.Equal(t, tc.want, resolvSearchDomain(tc.config))
	}
}

// Saving unchanged YAML must preserve null account semantics.
func TestEditorPreservesUnrestrictedAccounts(t *testing.T) {
	t.Setenv("EDITOR", "true")
	initial := inventory.Proposal{Names: []string{"host"}, PrincipalMode: inventory.AccountNamePrincipals}
	edited, err := editProposal(initial, bufio.NewReader(strings.NewReader("")))
	require.NoError(t, err)
	require.Nil(t, edited.Accounts)
}
