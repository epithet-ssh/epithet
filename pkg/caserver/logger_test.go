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

// mockCertLogger is a test implementation that captures logged events
type mockCertLogger struct {
	events []*CertEvent
	err    error
}

func (m *mockCertLogger) LogCert(ctx context.Context, event *CertEvent) error {
	m.events = append(m.events, event)
	return m.err
}

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
		Policy: policy.Policy{
			HostUsers: map[string][]string{
				"*.example.com": {"alice"},
			},
		},
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

func TestMultiCertLogger(t *testing.T) {
	mock1 := &mockCertLogger{}
	mock2 := &mockCertLogger{}
	mock3 := &mockCertLogger{}

	multiLogger := NewMultiCertLogger(mock1, mock2, mock3)

	event := &CertEvent{
		Timestamp:    time.Now(),
		SerialNumber: "99999",
		Identity:     "test@example.com",
		Principals:   []string{"test"},
		Connection: policy.Connection{
			RemoteHost: "test.example.com",
		},
	}

	err := multiLogger.LogCert(context.Background(), event)
	if err != nil {
		t.Fatalf("LogCert failed: %v", err)
	}

	// Verify all loggers received the event
	if len(mock1.events) != 1 {
		t.Errorf("Expected mock1 to receive 1 event, got %d", len(mock1.events))
	}
	if len(mock2.events) != 1 {
		t.Errorf("Expected mock2 to receive 1 event, got %d", len(mock2.events))
	}
	if len(mock3.events) != 1 {
		t.Errorf("Expected mock3 to receive 1 event, got %d", len(mock3.events))
	}

	// Verify events are the same
	if mock1.events[0].SerialNumber != "99999" {
		t.Errorf("Expected serial=99999 in mock1, got %s", mock1.events[0].SerialNumber)
	}
}

func TestMultiCertLogger_PartialFailure(t *testing.T) {
	mock1 := &mockCertLogger{}
	mock2 := &mockCertLogger{err: &testError{"mock2 error"}}
	mock3 := &mockCertLogger{}

	multiLogger := NewMultiCertLogger(mock1, mock2, mock3)

	event := &CertEvent{
		Timestamp:    time.Now(),
		SerialNumber: "88888",
	}

	err := multiLogger.LogCert(context.Background(), event)
	if err == nil {
		t.Fatal("Expected error from MultiCertLogger when one logger fails")
	}

	// Verify all loggers were called despite error
	if len(mock1.events) != 1 {
		t.Errorf("Expected mock1 to receive 1 event, got %d", len(mock1.events))
	}
	if len(mock2.events) != 1 {
		t.Errorf("Expected mock2 to receive 1 event, got %d", len(mock2.events))
	}
	if len(mock3.events) != 1 {
		t.Errorf("Expected mock3 to receive 1 event, got %d", len(mock3.events))
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

func TestCertEvent_toJSON(t *testing.T) {
	event := &CertEvent{
		Timestamp:    time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
		SerialNumber: "12345",
		Identity:     "alice@example.com",
		Principals:   []string{"alice", "admin"},
		Connection: policy.Connection{
			LocalHost:  "laptop.local",
			RemoteHost: "server.example.com",
			RemoteUser: "alice",
			Port:       22,
			Hash:       "abc123",
			ProxyJump:  "bastion.example.com",
		},
		ValidAfter:           time.Date(2025, 1, 15, 11, 59, 0, 0, time.UTC),
		ValidBefore:          time.Date(2025, 1, 15, 12, 10, 0, 0, time.UTC),
		Extensions:           map[string]string{"permit-pty": "", "permit-agent-forwarding": ""},
		PublicKeyFingerprint: "SHA256:abc123",
		Policy: policy.Policy{
			HostUsers: map[string][]string{
				"*.example.com": {"alice"},
			},
		},
	}

	jsonBytes, err := event.toJSON()
	if err != nil {
		t.Fatalf("toJSON failed: %v", err)
	}

	// Parse JSON to verify structure
	var parsed certEventForJSON
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Verify key fields
	if parsed.SerialNumber != "12345" {
		t.Errorf("Expected serial_number=12345, got %s", parsed.SerialNumber)
	}
	if parsed.Identity != "alice@example.com" {
		t.Errorf("Expected identity=alice@example.com, got %s", parsed.Identity)
	}
	if len(parsed.Principals) != 2 {
		t.Errorf("Expected 2 principals, got %d", len(parsed.Principals))
	}
	if parsed.RemoteHost != "server.example.com" {
		t.Errorf("Expected remote_host=server.example.com, got %s", parsed.RemoteHost)
	}
	if parsed.RemoteUser != "alice" {
		t.Errorf("Expected remote_user=alice, got %s", parsed.RemoteUser)
	}
	if parsed.Port != 22 {
		t.Errorf("Expected port=22, got %d", parsed.Port)
	}
	if parsed.Hash != "abc123" {
		t.Errorf("Expected hash=abc123, got %s", parsed.Hash)
	}
	if parsed.ProxyJump != "bastion.example.com" {
		t.Errorf("Expected proxy_jump=bastion.example.com, got %s", parsed.ProxyJump)
	}
	if parsed.PublicKeyFingerprint != "SHA256:abc123" {
		t.Errorf("Expected public_key_fingerprint=SHA256:abc123, got %s", parsed.PublicKeyFingerprint)
	}
	if len(parsed.HostUsers) != 1 || len(parsed.HostUsers["*.example.com"]) != 1 {
		t.Errorf("Expected host_users with *.example.com -> [alice], got %v", parsed.HostUsers)
	}
	if len(parsed.Extensions) != 2 {
		t.Errorf("Expected 2 extensions, got %d", len(parsed.Extensions))
	}

	// Verify timestamps
	if !parsed.Timestamp.Equal(event.Timestamp) {
		t.Errorf("Timestamp mismatch: expected %v, got %v", event.Timestamp, parsed.Timestamp)
	}
	if !parsed.ValidAfter.Equal(event.ValidAfter) {
		t.Errorf("ValidAfter mismatch: expected %v, got %v", event.ValidAfter, parsed.ValidAfter)
	}
	if !parsed.ValidBefore.Equal(event.ValidBefore) {
		t.Errorf("ValidBefore mismatch: expected %v, got %v", event.ValidBefore, parsed.ValidBefore)
	}
}

func TestCertEvent_toJSON_OmitsEmptyFields(t *testing.T) {
	event := &CertEvent{
		Timestamp:    time.Now(),
		SerialNumber: "12345",
		Identity:     "test@example.com",
		Principals:   []string{"test"},
		Connection: policy.Connection{
			RemoteHost: "test.example.com",
			RemoteUser: "test",
			Port:       22,
		},
		ValidAfter:  time.Now(),
		ValidBefore: time.Now().Add(10 * time.Minute),
		// Extensions is nil
		// ProxyJump is empty
	}

	jsonBytes, err := event.toJSON()
	if err != nil {
		t.Fatalf("toJSON failed: %v", err)
	}

	// Parse to map to check omitempty behavior
	var parsed map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// extensions should be omitted when nil
	if _, exists := parsed["extensions"]; exists {
		t.Error("Expected extensions to be omitted when nil")
	}

	// proxy_jump should be omitted when empty
	if _, exists := parsed["proxy_jump"]; exists {
		t.Error("Expected proxy_jump to be omitted when empty")
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
