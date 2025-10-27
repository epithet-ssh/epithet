package netstr

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncoder_Encode_Empty(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	err := enc.Encode([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	want := "0:,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncoder_Encode_Simple(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	err := enc.Encode([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	want := "5:hello,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncoder_Encode_Binary(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Test with binary data including null bytes
	data := []byte{0x00, 0x01, 0xFF, 0xFE}
	err := enc.Encode(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.Bytes()
	want := []byte("4:\x00\x01\xFF\xFE,")
	if !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEncoder_Encode_Large(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Test with 1000-byte payload
	data := bytes.Repeat([]byte("x"), 1000)
	err := enc.Encode(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	if !strings.HasPrefix(got, "1000:") {
		t.Errorf("expected prefix '1000:', got %q", got[:10])
	}
	if !strings.HasSuffix(got, ",") {
		t.Errorf("expected suffix ',', got %q", got[len(got)-5:])
	}
	if len(got) != len("1000:")+1000+1 {
		t.Errorf("expected length %d, got %d", len("1000:")+1000+1, len(got))
	}
}

func TestEncoder_EncodeKeyed_Simple(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	err := enc.EncodeKeyed('t', []byte("token"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	want := "6:ttoken,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncoder_EncodeKeyed_EmptyValue(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	err := enc.EncodeKeyed('k', []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	want := "1:k,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncoder_EncodeKeyed_MultipleFields(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Encode multiple keyed netstrings
	enc.EncodeKeyed('t', []byte("my-token"))
	enc.EncodeKeyed('s', []byte(`{"refresh":"xyz"}`))

	got := buf.String()
	want := "9:tmy-token,18:s{\"refresh\":\"xyz\"},"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncoder_EncodeString(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	err := enc.EncodeString("hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	want := "5:hello,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncoder_EncodeKeyedString(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	err := enc.EncodeKeyedString('e', "error message")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()
	want := "14:eerror message,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEncoder_Encode_SpecialCharacters(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Test with newlines, tabs, and other special chars
	data := []byte("hello\nworld\ttab\rcarriage")
	err := enc.Encode(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should encode exactly as-is, no escaping
	got := buf.String()
	want := "24:hello\nworld\ttab\rcarriage,"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
