package caserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
)

func TestSlogCertLogger(t *testing.T) {
	// Capture slog output
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	certLogger := NewSlogCertLogger(logger)

	event := &CertEvent{
		Timestamp:    time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
		SerialNumber: "12345",
		Identity:     "alice@example.com",
		Principals:   []string{"alice", "admin"},
		Connection: policy.Connection{
			RemoteHost: "server.example.com",
			RemoteUser: "alice",
			Port:       22,
			Hash:       "abc123",
		},
		ValidAfter:           time.Date(2025, 1, 15, 11, 59, 0, 0, time.UTC),
		ValidBefore:          time.Date(2025, 1, 15, 12, 10, 0, 0, time.UTC),
		Extensions:           map[string]string{"permit-pty": ""},
		PublicKeyFingerprint: "SHA256:abc123",
	}

	err := certLogger.LogCert(context.Background(), event)
	if err != nil {
		t.Fatalf("LogCert failed: %v", err)
	}

	// Verify output contains key fields
	output := buf.String()
	if output == "" {
		t.Fatal("No log output produced")
	}

	// Parse JSON log line
	var logEntry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output as JSON: %v", err)
	}

	// Check key fields are present
	if logEntry["serial"] != "12345" {
		t.Errorf("Expected serial=12345, got %v", logEntry["serial"])
	}
	if logEntry["identity"] != "alice@example.com" {
		t.Errorf("Expected identity=alice@example.com, got %v", logEntry["identity"])
	}
	if logEntry["remote_host"] != "server.example.com" {
		t.Errorf("Expected remote_host=server.example.com, got %v", logEntry["remote_host"])
	}
}

func TestNoopCertLogger(t *testing.T) {
	logger := NewNoopCertLogger()

	event := &CertEvent{
		Timestamp:    time.Now(),
		SerialNumber: "00000",
	}

	err := logger.LogCert(context.Background(), event)
	if err != nil {
		t.Errorf("NoopCertLogger should never return error, got: %v", err)
	}
}
