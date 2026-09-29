package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// resolveCAPubkey resolves the CA public key from a URL, file path, or literal key.
func resolveCAPubkey(input string, tlsCfg tlsconfig.Config, logger *slog.Logger) (string, error) {
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if err := tlsCfg.ValidateURL(input); err != nil {
			return "", err
		}

		httpClient, err := tlsconfig.NewHTTPClient(tlsCfg)
		if err != nil {
			return "", fmt.Errorf("failed to create HTTP client: %w", err)
		}

		if logger != nil {
			logger.Debug("http request", "method", "GET", "url", input)
		}

		start := time.Now()
		resp, err := httpClient.Get(input)
		duration := time.Since(start)
		if err != nil {
			if logger != nil {
				logger.Debug("http request failed", "method", "GET", "url", input, "duration_ms", duration.Milliseconds(), "error", err)
			}
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: %w", input, err)
		}
		defer resp.Body.Close()

		if logger != nil {
			logger.Debug("http response", "method", "GET", "url", input, "status", resp.StatusCode, "duration_ms", duration.Milliseconds())
		}

		if resp.StatusCode != 200 {
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: status %d", input, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from URL %s: %w", input, err)
		}

		return strings.TrimSpace(string(body)), nil
	}

	if _, err := os.Stat(input); err == nil {
		body, err := os.ReadFile(input)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from file %s: %w", input, err)
		}
		return strings.TrimSpace(string(body)), nil
	}

	if !strings.HasPrefix(input, "ssh-") && !strings.HasPrefix(input, "ecdsa-") {
		return "", fmt.Errorf("CA public key does not appear to be a valid SSH key (should start with ssh-* or ecdsa-*), not a valid URL, and file does not exist: %s", input)
	}

	return input, nil
}
