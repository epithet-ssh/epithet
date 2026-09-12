package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEditorCancelAndValidationRetry(t *testing.T) {
	t.Setenv("EDITOR", "true")
	initial := inventory.Proposal{Names: []string{"one"}, Labels: map[string]string{}, Accounts: []string{}, PrincipalMode: inventory.AccountNamePrincipals}
	_, err := editProposal(initial, bufio.NewReader(strings.NewReader("cancel\n")), "submit")
	require.ErrorIs(t, err, errCanceled)
	p, err := editProposal(initial, bufio.NewReader(strings.NewReader("submit\n")), "submit")
	require.NoError(t, err)
	require.Equal(t, initial, p)
	script := filepath.Join(t.TempDir(), "editor")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nif [ ! -f \"$1.once\" ]; then\n touch \"$1.once\"\n printf 'invalid: yaml\\n' > \"$1\"\nelse\n rm \"$1.once\"\n printf 'names: [fixed]\\naccounts: []\\nprincipal-mode: account-name\\n' > \"$1\"\nfi\n"), 0700))
	t.Setenv("EDITOR", script)
	p, err = editProposal(initial, bufio.NewReader(strings.NewReader("edit\nsubmit\n")), "submit")
	require.NoError(t, err)
	require.Equal(t, []string{"fixed"}, p.Names)
}
func TestManagedHostEnrollmentConfiguresBeforeSubmittingAndRetries(t *testing.T) {
	cmd, enrollment, env, runner, _, fragment := newSSHDConfigurationTest(t)
	pub := newTestCAPublicKey(t)
	var requests []inventoryapi.ControlRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<manage>; rel="https://epithet.dev/rel/inventory"`)
		fmt.Fprint(w, pub)
	})
	mux.HandleFunc("/manage", func(w http.ResponseWriter, r *http.Request) {
		_, err := os.Stat(fragment)
		require.NoError(t, err, "sshd setup precedes enrollment")
		var req inventoryapi.ControlRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		requests = append(requests, req)
		json.NewEncoder(w).Encode(inventoryapi.ControlResponse{Host: &inventory.HostRecord{ID: "record-123", Status: "pending"}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	cmd.CAURL = server.URL + "/"
	cmd.DomainFile = enrollment.DomainFile
	cmd.CAPubkeyFile = enrollment.CAPubkeyFile
	cmd.sshdEnv = env
	state, err := cmd.enrollState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	p := inventory.Proposal{Names: []string{"one.example"}, Accounts: []string{"alice"}, PrincipalMode: inventory.EpithetPrincipalV1, Domain: string(state.Domain)}
	data, err := yaml.Marshal(p)
	require.NoError(t, err)
	cmd.ProposalFile = filepath.Join(t.TempDir(), "proposal.yaml")
	require.NoError(t, os.WriteFile(cmd.ProposalFile, data, 0600))
	cmd.Yes = true
	first, err := cmd.enroll(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.Equal(t, "record-123", first.RecordID)
	require.NotEmpty(t, runner.calls)
	_, err = cmd.enroll(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.Len(t, requests, 2)
	require.Equal(t, requests[0].Credential, requests[1].Credential)
	require.Len(t, requests[0].Credential, 64)
	requireFileMode(t, filepath.Join(filepath.Dir(cmd.DomainFile), "enrollment.key"), 0600)
}
func TestEnrollmentCancelLeavesSSHDUnchanged(t *testing.T) {
	t.Setenv("EDITOR", "true")
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
	_, err = input.WriteString("cancel\n")
	require.NoError(t, err)
	_, err = input.Seek(0, 0)
	require.NoError(t, err)
	old := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = old }()
	_, err = cmd.enroll(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.ErrorIs(t, err, errCanceled)
	require.Empty(t, runner.calls)
	requireFileContents(t, main, "Port 22\n")
	_, err = os.Stat(fragment)
	require.ErrorIs(t, err, os.ErrNotExist)
}
