//go:build !darwin

// Package slogoslog provides a slog.Handler that writes to native OS logging systems.
package slogoslog

import "log/slog"

// NewHandler returns nil on non-Darwin platforms.
// The caller should fall back to the default handler when nil is returned.
func NewHandler(level slog.Leveler) slog.Handler {
	return nil
}
