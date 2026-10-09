package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestManagedEnrollmentLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, token, status    string
		realm, editedRealm     string
		rejected, localFailure bool
	}{
		{name: "pending", status: "pending"},
		{name: "token admission", token: "one-use-token", status: "active"},
		{name: "rejection then rerun", status: "pending", rejected: true},
		{name: "local failure", localFailure: true},
		{name: "named realm flag", status: "pending", realm: "fleet"},
		{name: "edited realm", status: "pending", editedRealm: "fleet"},
		{name: "edited flag realm", status: "pending", realm: "initial", editedRealm: "fleet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, local, env, runner, main, fragment := newSSHDConfigurationTest(t)
			cmd.RealmFile, cmd.CAPubkeyFile = local.RealmFile, local.CAPubkeyFile
			cmd.Names = []string{"one.example"}
			cmd.Token = tc.token
			cmd.PrincipalRealm = tc.realm
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
			t.Setenv("REALM", cmd.RealmFile)
			t.Setenv("CA_KEY", cmd.CAPubkeyFile)
			t.Setenv("FRAGMENT", fragment)
			t.Setenv("EDIT_REALM", tc.editedRealm)
			// The first review sees no installed state. Capture the actual proposal
			// so the test can compare its in-memory realm with the installed one.
			t.Setenv("EDITOR", `sh -c 'if [ ! -e "$REVIEW" ]; then test ! -e "$REALM" && test ! -e "$CA_KEY" && test ! -e "$FRAGMENT" || exit 9; fi; if [ -n "$EDIT_REALM" ]; then sed "/^realm:/d" "$1" > "$1.edit"; printf "realm: %s\n" "$EDIT_REALM" >> "$1.edit"; mv "$1.edit" "$1"; fi; cp "$1" "$REVIEW"' editor`)
			pub := newTestCAPublicKey(t)
			requests := make(chan inventoryapi.ControlRequest, 2)
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Link", `<manage>; rel="https://epithet.dev/rel/control"`)
				fmt.Fprint(w, pub)
			})
			mux.HandleFunc("/manage", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					json.NewEncoder(w).Encode(inventoryapi.Capabilities{Version: 1, Capabilities: []string{"enroll", "admin"}})
					return
				}
				var req inventoryapi.ControlRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				requests <- req
				require.FileExists(t, fragment, "local sshd configuration precedes submission")
				realm, err := principal.ReadRealmFile(cmd.RealmFile)
				require.NoError(t, err)
				require.Equal(t, string(realm), req.Host.Realm)
				if tc.rejected {
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(inventoryapi.ControlResponse{Error: "rejected"})
					return
				}
				json.NewEncoder(w).Encode(inventoryapi.ControlResponse{Host: &inventoryapi.HostRecord{ID: "record", Status: tc.status}})
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
			require.Len(t, runner.calls, 5)
			req := <-requests
			data, err := os.ReadFile(reviewFile)
			require.NoError(t, err)
			var reviewed inventory.Proposal
			require.NoError(t, yaml.Unmarshal(data, &reviewed))
			require.Equal(t, reviewed.ControlProposal(), *req.Host)
			if tc.editedRealm != "" {
				require.Equal(t, tc.editedRealm, reviewed.Realm)
			} else if tc.realm != "" {
				require.Equal(t, tc.realm, reviewed.Realm)
			}
			require.Equal(t, tc.token, req.Token)
			requireFileContents(t, cmd.CAPubkeyFile, string(pub))
			// A rerun reviews and submits anew, reusing local identity and skipping
			// reload when sshd is already configured. No prior record is resumed.
			tc.rejected = false
			cmd.Token = ""
			cmd.PrincipalRealm = ""
			tc.status = "pending"
			second, err := cmd.enroll(t.Context(), nil, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			require.Equal(t, "pending", second.Status)
			require.Equal(t, 2, resolutions)
			require.Len(t, runner.calls, 7, "unchanged setup only validates on rerun")
			require.False(t, second.RealmCreated)
			require.False(t, second.CAPublicKeyCreated)
			require.Equal(t, reviewed.Realm, string(second.Realm))
			resubmitted := <-requests
			require.Equal(t, reviewed.ControlProposal(), *resubmitted.Host)
			require.Empty(t, resubmitted.Token)
			require.NoFileExists(t, filepath.Join(filepath.Dir(cmd.RealmFile), "enrollment.key"))
		})
	}
}

func TestEnrollmentCancelLeavesPersistentStateUnchanged(t *testing.T) {
	t.Setenv("EDITOR", `sh -c ': > "$1"' editor`)
	cmd, enrollment, env, runner, main, fragment := newSSHDConfigurationTest(t)
	pub := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manage" {
			json.NewEncoder(w).Encode(inventoryapi.Capabilities{Version: 1, Capabilities: []string{"enroll", "admin"}})
			return
		}
		w.Header().Set("Link", `<manage>; rel="https://epithet.dev/rel/control"`)
		fmt.Fprint(w, pub)
	}))
	defer server.Close()
	cmd.CAURL = server.URL + "/"
	cmd.RealmFile = enrollment.RealmFile
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
	require.NoDirExists(t, filepath.Dir(cmd.RealmFile))
	require.NoFileExists(t, cmd.CAPubkeyFile)
	requireFileContents(t, main, "Port 22\n")
	_, err = os.Stat(fragment)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestProposedHostNamesUseConfiguredSearchSuffix(t *testing.T) {
	for _, tc := range []struct {
		name, realm string
		want        []string
	}{
		{"", "example.com", []string{}},
		{"host", "", []string{"host"}},
		{"HOST", "Example.COM.", []string{"host.example.com"}},
		{"HOST.Example.COM.", "example.com", []string{"host.example.com"}},
		{"host.notexample.com", "example.com", []string{"host.notexample.com.example.com"}},
	} {
		require.Equal(t, tc.want, proposedHostNames(tc.name, tc.realm))
	}
	for _, tc := range []struct{ config, want string }{
		{"nameserver 127.0.0.1\n", ""},
		{"# search ignored\nsearch home.example another.example # comment\n", "home.example"},
		{"realm home.example\n", "home.example"},
		{"realm old.example\nsearch new.example other.example\n", "new.example"},
	} {
		require.Equal(t, tc.want, resolvSearchRealm(tc.config))
	}
}

func TestDirectoryOnlyManagementDoesNotEnableHostEnrollment(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		fail       bool
	}{
		{"directory only", `{"version":1,"capabilities":["admin","directory"]}`, 200, false},
		{"unavailable", `{}`, 503, true},
		{"invalid response", `{}`, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "GET", r.Method)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			cmd := HostEnrollCLI{}
			enrollment := &hostEnrollment{CAFinalURL: server.URL + "/", AdvertisedLinkFields: []string{`<manage>; rel="https://epithet.dev/rel/control"`}}
			registration, e := cmd.prepareRegistration(t.Context(), enrollment, nil, tlsconfig.Config{Insecure: true})
			require.Nil(t, registration)
			if tc.fail {
				require.Error(t, e)
			} else {
				require.NoError(t, e)
				cmd.Token = "token"
				_, e = cmd.prepareRegistration(t.Context(), enrollment, nil, tlsconfig.Config{Insecure: true})
				require.ErrorContains(t, e, "does not advertise")
			}
		})
	}
}
