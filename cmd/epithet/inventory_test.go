package main

import (
	"encoding/json"
	"fmt"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestInventoryDisplayPreservesRevisionAndPattern(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer output.Close()
	original := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = original }()
	record := facts.HostRecord{
		ID:       strings.Repeat("a", 64),
		Revision: 9007199254740993,
		Proposal: facts.Proposal{Pattern: "*.example", PrincipalMode: "account-name"},
	}
	require.NoError(t, printInventory(record))
	_, err = output.Seek(0, 0)
	require.NoError(t, err)
	data, err := io.ReadAll(output)
	require.NoError(t, err)
	var fields map[string]yaml.Node
	require.NoError(t, yaml.Unmarshal(data, &fields))
	var revision uint64
	revisionNode := fields["revision"]
	require.NoError(t, revisionNode.Decode(&revision))
	require.Equal(t, record.Revision, revision)
	var host inventory.Proposal
	hostNode := fields["host"]
	require.NoError(t, hostNode.Decode(&host))
	require.Nil(t, host.Accounts)
	require.Equal(t, "*.example", host.Pattern)
}

func TestInventoryFindAcrossPages(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprintf("ambiguous=%t", ambiguous), func(t *testing.T) {
			first := make([]facts.HostRecord, inventory.DefaultPageLimit)
			for n := range first {
				first[n] = facts.HostRecord{ID: fmt.Sprintf("%064x", n+1), Proposal: facts.Proposal{Names: []string{"other"}}}
			}
			if ambiguous {
				first[0].Proposal.Names = []string{"wanted"}
			}
			last := facts.HostRecord{ID: fmt.Sprintf("%064x", len(first)+1), Proposal: facts.Proposal{Names: []string{"wanted"}}}
			// Unix socket paths have a small platform limit; t.TempDir includes the
			// full subtest name and can exceed it on macOS.
			socketDir, err := os.MkdirTemp("", "ep-find-")
			require.NoError(t, err)
			t.Cleanup(func() { os.RemoveAll(socketDir) })
			socket := filepath.Join(socketDir, "s")
			listener, err := net.Listen("unix", socket)
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			done := make(chan error, 1)
			go func() {
				for n, page := range [][]facts.HostRecord{first, {last}} {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					var req broker.Request
					err = json.NewDecoder(conn).Decode(&req)
					wantAfter := ""
					if n == 1 {
						wantAfter = first[len(first)-1].ID
					}
					if err == nil && (req.Inventory == nil || req.Inventory.Action != "list" || req.Inventory.After != wantAfter || req.Inventory.Limit != inventory.DefaultPageLimit) {
						err = fmt.Errorf("unexpected pagination request: %+v", req.Inventory)
					}
					if err == nil {
						err = json.NewEncoder(conn).Encode(broker.Event{Inventory: &broker.InventoryResponse{ControlResponse: facts.ControlResponse{Hosts: page}}})
					}
					conn.Close()
					if err != nil {
						done <- err
						return
					}
				}
				if !ambiguous {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					var req broker.Request
					err = json.NewDecoder(conn).Decode(&req)
					if err == nil && (req.Inventory == nil || req.Inventory.Action != "get" || req.Inventory.ID != last.ID) {
						err = fmt.Errorf("expected selected record GET")
					}
					if err == nil {
						last.Revision = 2
						err = json.NewEncoder(conn).Encode(broker.Event{Inventory: &broker.InventoryResponse{ControlResponse: facts.ControlResponse{Host: &last}}})
					}
					conn.Close()
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			cli := InventoryCLI{ManagementCLI: ManagementCLI{Broker: socket}}
			h, err := cli.find("wanted")
			if ambiguous {
				require.ErrorContains(t, err, "ambiguous host")
			} else {
				require.NoError(t, err)
				require.Equal(t, last.ID, h.ID)
			}
			require.NoError(t, <-done)
		})
	}
}

func TestInventoryAutomationUsesConfiguredCredential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/manage", r.URL.Path)
		require.Equal(t, "Bearer automation-secret", r.Header.Get("Authorization"))
		var req facts.ControlRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, "list", req.Action)
		json.NewEncoder(w).Encode(facts.ControlResponse{Hosts: []facts.HostRecord{}})
	}))
	defer server.Close()
	token := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(token, []byte("automation-secret\n"), 0600))
	c := InventoryCLI{ControlURL: server.URL + "/manage", AdminTokenFile: token}
	require.NoError(t, c.BeforeRun(tlsconfig.Config{Insecure: true}))
	_, err := c.request(facts.ControlRequest{Action: "list"})
	require.NoError(t, err)
	c.ControlURL = ""
	_, err = c.request(facts.ControlRequest{Action: "list"})
	require.ErrorContains(t, err, "both --control-url and --admin-token-file")
}
