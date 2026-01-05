//go:build darwin

// Package slogoslog provides a slog.Handler that writes to Apple's Unified Logging system (os_log).
package slogoslog

/*
#cgo LDFLAGS: -framework Foundation
#include <os/log.h>
#include <stdlib.h>

static os_log_t epithet_log = NULL;

void epithet_log_init(const char* subsystem, const char* category) {
    epithet_log = os_log_create(subsystem, category);
}

void epithet_log_debug(const char* msg) {
    os_log_debug(epithet_log, "%{public}s", msg);
}

void epithet_log_info(const char* msg) {
    os_log_info(epithet_log, "%{public}s", msg);
}

void epithet_log_default(const char* msg) {
    os_log(epithet_log, "%{public}s", msg);
}

void epithet_log_error(const char* msg) {
    os_log_error(epithet_log, "%{public}s", msg);
}
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"unsafe"
)

const (
	// Subsystem is the os_log subsystem identifier for epithet.
	Subsystem = "dev.epithet"
	// Category is the default os_log category.
	Category = "default"
)

var initOnce sync.Once

// Handler is a slog.Handler that writes to Apple's Unified Logging system.
type Handler struct {
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
}

// NewHandler creates a new os_log handler with the given minimum log level.
// Returns a handler that writes to Apple's Unified Logging system with
// subsystem "dev.epithet".
func NewHandler(level slog.Leveler) slog.Handler {
	initOnce.Do(func() {
		cs := C.CString(Subsystem)
		cc := C.CString(Category)
		defer C.free(unsafe.Pointer(cs))
		defer C.free(unsafe.Pointer(cc))
		C.epithet_log_init(cs, cc)
	})
	return &Handler{level: level}
}

// Enabled reports whether the handler handles records at the given level.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

// Handle writes the record to os_log.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	msg := h.formatRecord(r)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))

	switch {
	case r.Level >= slog.LevelError:
		C.epithet_log_error(cmsg)
	case r.Level >= slog.LevelWarn:
		C.epithet_log_default(cmsg)
	case r.Level >= slog.LevelInfo:
		C.epithet_log_info(cmsg)
	default:
		C.epithet_log_debug(cmsg)
	}
	return nil
}

// WithAttrs returns a new handler with the given attributes added.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	newAttrs = append(newAttrs, attrs...)
	return &Handler{
		level:  h.level,
		attrs:  newAttrs,
		groups: h.groups,
	}
}

// WithGroup returns a new handler with the given group name added.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	newGroups := make([]string, len(h.groups), len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups = append(newGroups, name)
	return &Handler{
		level:  h.level,
		attrs:  h.attrs,
		groups: newGroups,
	}
}

// formatRecord formats a log record as "message key=value key=value ...".
func (h *Handler) formatRecord(r slog.Record) string {
	var b strings.Builder
	b.WriteString(r.Message)

	// Write pre-accumulated attrs.
	for _, a := range h.attrs {
		h.writeAttr(&b, a, h.groups)
	}

	// Write record attrs.
	r.Attrs(func(a slog.Attr) bool {
		h.writeAttr(&b, a, h.groups)
		return true
	})

	return b.String()
}

// writeAttr writes a single attribute to the builder.
func (h *Handler) writeAttr(b *strings.Builder, a slog.Attr, groups []string) {
	// Resolve the attribute value.
	a.Value = a.Value.Resolve()

	// Skip empty attributes.
	if a.Equal(slog.Attr{}) {
		return
	}

	b.WriteByte(' ')

	// Write group prefix.
	for _, g := range groups {
		b.WriteString(g)
		b.WriteByte('.')
	}

	// Handle groups specially.
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		newGroups := groups
		if a.Key != "" {
			newGroups = append(groups, a.Key)
		}
		for _, ga := range attrs {
			h.writeAttr(b, ga, newGroups)
		}
		return
	}

	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(formatValue(a.Value))
}

// formatValue formats a slog.Value for display.
func formatValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if strings.ContainsAny(s, " \t\n\"") {
			return fmt.Sprintf("%q", s)
		}
		return s
	case slog.KindTime:
		return v.Time().Format("15:04:05.000")
	case slog.KindDuration:
		return v.Duration().String()
	default:
		return fmt.Sprintf("%v", v.Any())
	}
}
