package writpolicy

import (
	"testing"
)

func TestDefaultExtensions(t *testing.T) {
	ext := defaultExtensions()

	if len(ext) != 3 {
		t.Errorf("expected 3 default extensions, got %d", len(ext))
	}

	if _, ok := ext["permit-pty"]; !ok {
		t.Error("expected permit-pty extension")
	}
}

func TestDefaultExpiration(t *testing.T) {
	exp := defaultExpiration()

	if exp != "5m" {
		t.Errorf("expected default expiration '5m', got %s", exp)
	}
}
