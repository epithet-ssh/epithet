package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/caclient"
)

func TestReplaceEnv_ExistingKey(t *testing.T) {
	env := []string{"HOME=/home/user", "SSH_AUTH_SOCK=/old/path", "SHELL=/bin/fish"}
	result := replaceEnv(env, "SSH_AUTH_SOCK", "/new/path")

	found := false
	for _, e := range result {
		if e == "SSH_AUTH_SOCK=/new/path" {
			found = true
		}
		if e == "SSH_AUTH_SOCK=/old/path" {
			t.Error("old value still present")
		}
	}
	if !found {
		t.Error("new value not found")
	}
	if len(result) != 3 {
		t.Errorf("expected 3 entries, got %d", len(result))
	}
}

func TestReplaceEnv_NewKey(t *testing.T) {
	env := []string{"HOME=/home/user", "SHELL=/bin/fish"}
	result := replaceEnv(env, "SSH_AUTH_SOCK", "/new/path")

	found := false
	for _, e := range result {
		if e == "SSH_AUTH_SOCK=/new/path" {
			found = true
		}
	}
	if !found {
		t.Error("new key not appended")
	}
	if len(result) != 3 {
		t.Errorf("expected 3 entries, got %d", len(result))
	}
}

func TestReplaceEnv_EmptyEnv(t *testing.T) {
	result := replaceEnv(nil, "KEY", "value")
	if len(result) != 1 || result[0] != "KEY=value" {
		t.Errorf("expected [KEY=value], got %v", result)
	}
}

func TestWaitForBrokerStartup_ReturnsServeError(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	agentDir := filepath.Join(tempDir, "agent")
	if err := os.MkdirAll(agentDir, 0700); err != nil {
		t.Fatalf("mkdir agent dir: %v", err)
	}

	endpoints := []caclient.CAEndpoint{{URL: "http://127.0.0.1", Priority: caclient.DefaultPriority}}
	caClient, err := caclient.New(endpoints)
	if err != nil {
		t.Fatalf("create CA client: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	socketPath := filepath.Join(tempDir, strings.Repeat("sock", 40))
	b, err := broker.New(*logger, socketPath, "true", caClient, agentDir)
	if err != nil {
		t.Fatalf("create broker: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	brokerErr := make(chan error, 1)
	go func() {
		brokerErr <- b.Serve(ctx)
	}()

	err = waitForBrokerStartup(b, brokerErr)
	if err == nil {
		t.Fatal("expected startup error, got nil")
	}
	if !strings.Contains(err.Error(), "broker failed to start") {
		t.Fatalf("expected startup failure wrapper, got %v", err)
	}
}
