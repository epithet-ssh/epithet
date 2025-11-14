package caserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
)

// CertLogger logs certificate issuance events for audit, compliance, and analytics.
type CertLogger interface {
	LogCert(ctx context.Context, event *CertEvent) error
}

// CertEvent contains all information about a certificate issuance event.
type CertEvent struct {
	Timestamp            time.Time
	SerialNumber         string
	Identity             string
	Principals           []string
	Connection           policy.Connection
	ValidAfter           time.Time
	ValidBefore          time.Time
	Extensions           map[string]string
	PublicKeyFingerprint string
	Policy               policy.Policy
}

// SlogCertLogger logs certificate events using structured logging (slog).
// Works with any slog handler (text, JSON, CloudWatch, etc.).
type SlogCertLogger struct {
	logger *slog.Logger
}

// NewSlogCertLogger creates a new certificate logger that emits structured logs.
func NewSlogCertLogger(logger *slog.Logger) *SlogCertLogger {
	return &SlogCertLogger{logger: logger}
}

// LogCert emits a structured log event with all certificate details.
func (l *SlogCertLogger) LogCert(ctx context.Context, event *CertEvent) error {
	l.logger.InfoContext(ctx, "certificate issued",
		slog.String("serial", event.SerialNumber),
		slog.String("identity", event.Identity),
		slog.Any("principals", event.Principals),
		slog.String("remote_host", event.Connection.RemoteHost),
		slog.String("remote_user", event.Connection.RemoteUser),
		slog.Int("port", int(event.Connection.Port)),
		slog.String("hash", string(event.Connection.Hash)),
		slog.String("proxy_jump", event.Connection.ProxyJump),
		slog.Time("valid_after", event.ValidAfter),
		slog.Time("valid_before", event.ValidBefore),
		slog.Any("extensions", event.Extensions),
		slog.String("public_key_fingerprint", event.PublicKeyFingerprint),
		slog.String("host_pattern", event.Policy.HostPattern),
	)
	return nil
}

// MultiCertLogger calls multiple CertLoggers in sequence.
// Best-effort: calls all loggers and collects errors, but doesn't stop on first error.
type MultiCertLogger struct {
	loggers []CertLogger
}

// NewMultiCertLogger creates a logger that calls multiple loggers.
func NewMultiCertLogger(loggers ...CertLogger) *MultiCertLogger {
	return &MultiCertLogger{loggers: loggers}
}

// LogCert calls all loggers and returns a combined error if any fail.
func (m *MultiCertLogger) LogCert(ctx context.Context, event *CertEvent) error {
	var errs []error
	for _, logger := range m.loggers {
		if err := logger.LogCert(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cert logging errors: %v", errs)
	}
	return nil
}

// NoopCertLogger is a logger that does nothing.
// Used when certificate logging is disabled.
type NoopCertLogger struct{}

// NewNoopCertLogger creates a no-op logger.
func NewNoopCertLogger() *NoopCertLogger {
	return &NoopCertLogger{}
}

// LogCert does nothing and always returns nil.
func (n *NoopCertLogger) LogCert(ctx context.Context, event *CertEvent) error {
	return nil
}

// certEventForJSON is a JSON-friendly representation of CertEvent.
// Used by S3CertArchiver and other JSON-based loggers.
type certEventForJSON struct {
	Timestamp            time.Time         `json:"timestamp"`
	SerialNumber         string            `json:"serial_number"`
	Identity             string            `json:"identity"`
	Principals           []string          `json:"principals"`
	RemoteHost           string            `json:"remote_host"`
	RemoteUser           string            `json:"remote_user"`
	Port                 int               `json:"port"`
	Hash                 string            `json:"hash"`
	ProxyJump            string            `json:"proxy_jump,omitempty"`
	ValidAfter           time.Time         `json:"valid_after"`
	ValidBefore          time.Time         `json:"valid_before"`
	Extensions           map[string]string `json:"extensions,omitempty"`
	PublicKeyFingerprint string            `json:"public_key_fingerprint"`
	HostPattern          string            `json:"host_pattern"`
}

// toJSON converts a CertEvent to JSON bytes.
func (e *CertEvent) toJSON() ([]byte, error) {
	je := certEventForJSON{
		Timestamp:            e.Timestamp,
		SerialNumber:         e.SerialNumber,
		Identity:             e.Identity,
		Principals:           e.Principals,
		RemoteHost:           e.Connection.RemoteHost,
		RemoteUser:           e.Connection.RemoteUser,
		Port:                 int(e.Connection.Port),
		Hash:                 string(e.Connection.Hash),
		ProxyJump:            e.Connection.ProxyJump,
		ValidAfter:           e.ValidAfter,
		ValidBefore:          e.ValidBefore,
		Extensions:           e.Extensions,
		PublicKeyFingerprint: e.PublicKeyFingerprint,
		HostPattern:          e.Policy.HostPattern,
	}
	return json.Marshal(je)
}
