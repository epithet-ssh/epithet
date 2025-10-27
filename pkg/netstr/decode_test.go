package netstr

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDecoder_Decode_Empty(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("0:,")))
	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
}

func TestDecoder_Decode_Simple(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,")))
	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q, want %q", string(data), "hello")
	}
}

func TestDecoder_Decode_Binary(t *testing.T) {
	input := []byte("4:\x00\x01\xFF\xFE,")
	dec := NewDecoder(bytes.NewReader(input))
	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x00, 0x01, 0xFF, 0xFE}
	if !bytes.Equal(data, want) {
		t.Errorf("got %v, want %v", data, want)
	}
}

func TestDecoder_Decode_Multiple(t *testing.T) {
	input := "5:hello,5:world,3:foo,"
	dec := NewDecoder(bytes.NewReader([]byte(input)))

	// First netstring
	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("unexpected error on first decode: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	// Second netstring
	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("unexpected error on second decode: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}

	// Third netstring
	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("unexpected error on third decode: %v", err)
	}
	if string(data) != "foo" {
		t.Errorf("third: got %q, want %q", string(data), "foo")
	}

	// EOF
	_, err = dec.Decode()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestDecoder_DecodeKeyed_Simple(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("6:ttoken,")))
	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != 't' {
		t.Errorf("got key %q, want 't'", key)
	}
	if string(value) != "token" {
		t.Errorf("got value %q, want %q", string(value), "token")
	}
}

func TestDecoder_DecodeKeyed_EmptyValue(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("1:k,")))
	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != 'k' {
		t.Errorf("got key %q, want 'k'", key)
	}
	if len(value) != 0 {
		t.Errorf("expected empty value, got %d bytes", len(value))
	}
}

func TestDecoder_DecodeKeyed_Multiple(t *testing.T) {
	input := "9:tmy-token,18:s{\"refresh\":\"xyz\"},"
	dec := NewDecoder(bytes.NewReader([]byte(input)))

	// First keyed netstring
	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("unexpected error on first decode: %v", err)
	}
	if key != 't' {
		t.Errorf("first: got key %q, want 't'", key)
	}
	if string(value) != "my-token" {
		t.Errorf("first: got value %q, want %q", string(value), "my-token")
	}

	// Second keyed netstring
	key, value, err = dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("unexpected error on second decode: %v", err)
	}
	if key != 's' {
		t.Errorf("second: got key %q, want 's'", key)
	}
	if string(value) != `{"refresh":"xyz"}` {
		t.Errorf("second: got value %q, want %q", string(value), `{"refresh":"xyz"}`)
	}
}

func TestDecoder_Decode_EOF(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte{}))
	_, err := dec.Decode()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestDecoder_Decode_InvalidFormat_MissingColon(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("5hello,")))
	_, err := dec.Decode()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestDecoder_Decode_InvalidFormat_MissingComma(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("5:hello")))
	_, err := dec.Decode()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var formatErr *FormatError
	if !errors.As(err, &formatErr) {
		t.Errorf("expected FormatError, got %T", err)
	}
}

func TestDecoder_Decode_InvalidFormat_WrongComma(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("5:hello!")))
	_, err := dec.Decode()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "expected ','") {
		t.Errorf("expected error about comma, got %v", err)
	}
}

func TestDecoder_Decode_InvalidFormat_TruncatedPayload(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("10:hello,")))
	_, err := dec.Decode()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("expected EOF error, got %v", err)
	}
}

func TestDecoder_Decode_InvalidFormat_LeadingZero(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("05:hello,")))
	_, err := dec.Decode()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "leading zero") {
		t.Errorf("expected leading zero error, got %v", err)
	}
}

func TestDecoder_Decode_InvalidFormat_EmptyLength(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte(":hello,")))
	_, err := dec.Decode()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty length error, got %v", err)
	}
}

func TestDecoder_Decode_MaxLength(t *testing.T) {
	// Create decoder with small max length
	dec := NewDecoder(bytes.NewReader([]byte("100:x")), MaxLength(10))
	_, err := dec.Decode()
	if err != ErrTooLarge {
		t.Errorf("expected ErrTooLarge, got %v", err)
	}
}

func TestDecoder_DecodeKeyed_InvalidFormat_ZeroLength(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("0:,")))
	_, _, err := dec.DecodeKeyed()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "length >= 1") {
		t.Errorf("expected length error, got %v", err)
	}
}

func TestDecoder_Decode_StrictMode_RejectsWhitespace(t *testing.T) {
	// Strict mode (default) should reject whitespace between netstrings
	dec := NewDecoder(bytes.NewReader([]byte("5:hello, 5:world,")))

	// First decode should succeed
	_, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}

	// Second decode should fail due to leading space
	_, err = dec.Decode()
	if err == nil {
		t.Fatal("expected error for whitespace in strict mode, got nil")
	}
	// In strict mode, any non-digit character (including whitespace) causes an error
	// We just verify that an error occurred; the specific message may vary
}

func TestDecoder_Decode_PreservesWhitespaceInPayload(t *testing.T) {
	// Whitespace inside the payload should always be preserved
	dec := NewDecoder(bytes.NewReader([]byte("11:hello world,")))
	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("whitespace not preserved, got %q", string(data))
	}
}
