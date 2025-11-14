package caserver

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3CertArchiver archives certificate events to S3 with date partitioning.
// Uses async buffered writes for performance. Best-effort: logs errors but doesn't fail cert issuance.
type S3CertArchiver struct {
	s3Client  *s3.Client
	bucket    string
	keyPrefix string
	logger    *slog.Logger

	events chan *CertEvent
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// S3ArchiverConfig configures the S3 certificate archiver.
type S3ArchiverConfig struct {
	S3Client   *s3.Client
	Bucket     string
	KeyPrefix  string          // Optional prefix for S3 keys (e.g., "certs/")
	Logger     *slog.Logger    // For logging archiver errors
	BufferSize int             // Channel buffer size (default: 100)
}

// NewS3CertArchiver creates a new S3 archiver with async background writes.
func NewS3CertArchiver(config S3ArchiverConfig) *S3CertArchiver {
	if config.BufferSize == 0 {
		config.BufferSize = 100
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	archiver := &S3CertArchiver{
		s3Client:  config.S3Client,
		bucket:    config.Bucket,
		keyPrefix: config.KeyPrefix,
		logger:    config.Logger,
		events:    make(chan *CertEvent, config.BufferSize),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Start background writer
	archiver.wg.Add(1)
	go archiver.writer()

	return archiver
}

// LogCert enqueues a certificate event for async S3 archival.
// Non-blocking: drops events if buffer is full (best-effort).
func (a *S3CertArchiver) LogCert(ctx context.Context, event *CertEvent) error {
	select {
	case a.events <- event:
		return nil
	default:
		// Buffer full - drop event and log warning
		a.logger.Warn("cert archiver buffer full, dropping event",
			slog.String("serial", event.SerialNumber))
		return fmt.Errorf("archiver buffer full")
	}
}

// Shutdown gracefully stops the archiver and flushes pending events.
// Blocks until all pending events are written or timeout is reached.
func (a *S3CertArchiver) Shutdown(timeout time.Duration) error {
	a.cancel()

	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("shutdown timeout after %v", timeout)
	}
}

// writer is the background goroutine that writes events to S3.
func (a *S3CertArchiver) writer() {
	defer a.wg.Done()

	for {
		select {
		case event := <-a.events:
			if err := a.writeEvent(event); err != nil {
				a.logger.Error("failed to archive cert to S3",
					slog.String("serial", event.SerialNumber),
					slog.String("error", err.Error()))
			}
		case <-a.ctx.Done():
			// Drain remaining events
			a.drainEvents()
			return
		}
	}
}

// drainEvents writes all remaining buffered events before shutdown.
func (a *S3CertArchiver) drainEvents() {
	for {
		select {
		case event := <-a.events:
			if err := a.writeEvent(event); err != nil {
				a.logger.Error("failed to archive cert during shutdown",
					slog.String("serial", event.SerialNumber),
					slog.String("error", err.Error()))
			}
		default:
			return
		}
	}
}

// writeEvent writes a single event to S3 with date partitioning.
func (a *S3CertArchiver) writeEvent(event *CertEvent) error {
	// Generate S3 key with date partitioning
	key := a.generateKey(event.Timestamp, event.SerialNumber)

	// Convert event to JSON
	jsonBytes, err := event.toJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Append newline for JSONL format
	jsonBytes = append(jsonBytes, '\n')

	// Write to S3
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = a.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(a.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(jsonBytes),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("failed to write to S3: %w", err)
	}

	a.logger.Debug("archived cert to S3",
		slog.String("bucket", a.bucket),
		slog.String("key", key),
		slog.String("serial", event.SerialNumber))

	return nil
}

// generateKey creates an S3 key with date partitioning and unique serial number.
// Format: [prefix/]year=YYYY/month=MM/day=DD/serial-NNNNNN.json
func (a *S3CertArchiver) generateKey(timestamp time.Time, serial string) string {
	year, month, day := timestamp.Date()

	key := fmt.Sprintf("year=%04d/month=%02d/day=%02d/serial-%s.json",
		year, int(month), day, serial)

	if a.keyPrefix != "" {
		key = a.keyPrefix + "/" + key
	}

	return key
}
