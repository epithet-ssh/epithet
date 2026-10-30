package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/stretchr/testify/require"
)

func fakeBrokerClient(t *testing.T, serve func(net.Conn)) brokerClient {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "epithet-client-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "b.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serve(conn)
	}()
	return brokerClient{socket: socket}
}

func TestBrokerClientMatchDenialAndProgress(t *testing.T) {
	client := fakeBrokerClient(t, func(conn net.Conn) {
		var request broker.Request
		if json.NewDecoder(conn).Decode(&request) != nil || request.Match == nil {
			t.Error("expected match request")
			return
		}
		enc := json.NewEncoder(conn)
		_ = enc.Encode(broker.Event{Output: "auth progress\n"})
		_ = enc.Encode(broker.Event{Result: &broker.MatchResponse{Allow: false, Error: "policy denied"}})
	})
	var progress bytes.Buffer
	result, err := client.match(t.Context(), wire.Connection{RemoteHost: "host"}, &progress)
	require.NoError(t, err)
	require.False(t, result.Allow)
	require.Equal(t, "policy denied", result.Error)
	require.Equal(t, "auth progress\n", progress.String())
}

func TestBrokerClientManagementRetainsLargeResponseLimit(t *testing.T) {
	// Management pages can exceed the ordinary agent-event limit.
	large := strings.Repeat("x", scannerBufferSize+1)
	client := fakeBrokerClient(t, func(conn net.Conn) {
		var request broker.Request
		if json.NewDecoder(conn).Decode(&request) != nil || request.Inventory == nil {
			t.Error("expected management request")
			return
		}
		_ = json.NewEncoder(conn).Encode(broker.Event{Inventory: &broker.InventoryResponse{CAURL: large}})
	})
	result, err := client.manage(t.Context(), facts.ControlRequest{Action: "hosts"}, nil)
	require.NoError(t, err)
	require.Equal(t, large, result.CAURL)
}

func TestBrokerClientCancellationClosesConnection(t *testing.T) {
	readRequest := make(chan struct{})
	closed := make(chan struct{})
	client := fakeBrokerClient(t, func(conn net.Conn) {
		var request broker.Request
		if json.NewDecoder(conn).Decode(&request) != nil {
			return
		}
		close(readRequest)
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.identity(ctx, nil, "")
		done <- err
	}()
	select {
	case <-readRequest:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not receive request")
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not close connection")
	}
}
