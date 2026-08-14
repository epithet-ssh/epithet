package caserver

import (
	"context"
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
	CertFingerprint      string
	PublicKeyFingerprint string
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
		slog.String("proxy_jump", event.Connection.ProxyJump),
		slog.Time("valid_after", event.ValidAfter),
		slog.Time("valid_before", event.ValidBefore),
		slog.Any("extensions", event.Extensions),
		slog.String("cert_fingerprint", event.CertFingerprint),
		slog.String("public_key_fingerprint", event.PublicKeyFingerprint),
	)
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
