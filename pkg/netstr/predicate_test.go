package netstr

import (
	"bytes"
	"io"
	"testing"
)

func TestDecoder_SkipNone(t *testing.T) {
	// SkipNone should behave like strict mode - reject whitespace
	dec := NewDecoder(bytes.NewReader([]byte("5:hello, 5:world,")), SkipNone())

	// First decode should succeed
	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	// Second decode should fail due to space before "5"
	_, err = dec.Decode()
	if err == nil {
		t.Fatal("expected error for whitespace in strict mode, got nil")
	}
}

func TestDecoder_SkipNone_Default(t *testing.T) {
	// Default (no options) should skip nothing (strict mode)
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\n5:world,")))

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	// Should fail on newline
	_, err = dec.Decode()
	if err == nil {
		t.Fatal("expected error for newline in strict mode, got nil")
	}
}

func TestDecoder_SkipASCIIWhitespace_Space(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,   5:world,")), SkipASCIIWhitespace())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}
}

func TestDecoder_SkipASCIIWhitespace_IncludesVerticalTab(t *testing.T) {
	// SkipASCIIWhitespace now uses unicode.IsSpace, so it includes \v
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\v5:world,")), SkipASCIIWhitespace())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}
}

func TestDecoder_SkipASCIIWhitespace_IncludesFormFeed(t *testing.T) {
	// SkipASCIIWhitespace now uses unicode.IsSpace, so it includes \f
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\f5:world,")), SkipASCIIWhitespace())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}
}

func TestDecoder_SkipASCIIWhitespace_AllTypes(t *testing.T) {
	// SkipASCIIWhitespace now includes all ASCII whitespace: space, tab, \n, \r, \v, \f
	dec := NewDecoder(bytes.NewReader([]byte("5:hello, \t\n\r\v\f5:world,")), SkipASCIIWhitespace())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}
}

func TestDecoder_SkipUnicodeWhitespace_NEL(t *testing.T) {
	// SkipUnicodeWhitespace should skip 0x85 (NEL - Next Line)
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\x855:world,")), SkipUnicodeWhitespace())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}
}

func TestDecoder_SkipUnicodeWhitespace_NBSP(t *testing.T) {
	// SkipUnicodeWhitespace should skip 0xA0 (NBSP - Non-Breaking Space)
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\xA05:world,")), SkipUnicodeWhitespace())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}
}

func TestDecoder_SkipASCIIWhitespace_RejectsNEL(t *testing.T) {
	// SkipASCIIWhitespace should NOT skip 0x85 (non-ASCII)
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\x855:world,")), SkipASCIIWhitespace())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	// Should fail on 0x85
	_, err = dec.Decode()
	if err == nil {
		t.Fatal("expected error for NEL (0x85) with ASCII whitespace skip, got nil")
	}
}

func TestDecoder_SkipASCIIWhitespace_RejectsNBSP(t *testing.T) {
	// SkipASCIIWhitespace should NOT skip 0xA0 (non-ASCII)
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\xA05:world,")), SkipASCIIWhitespace())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	// Should fail on 0xA0
	_, err = dec.Decode()
	if err == nil {
		t.Fatal("expected error for NBSP (0xA0) with ASCII whitespace skip, got nil")
	}
}

func TestDecoder_SkipBytes_CustomPredicate_OnlyNewlines(t *testing.T) {
	// Custom predicate that only skips newlines
	onlyNewlines := func(b byte) bool { return b == '\n' }
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\n\n5:world,")), SkipBytes(onlyNewlines))

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}
}

func TestDecoder_SkipBytes_CustomPredicate_RejectsSpaces(t *testing.T) {
	// Custom predicate that only skips newlines (NOT spaces)
	onlyNewlines := func(b byte) bool { return b == '\n' }
	dec := NewDecoder(bytes.NewReader([]byte("5:hello, 5:world,")), SkipBytes(onlyNewlines))

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	// Should fail on space (not in predicate)
	_, err = dec.Decode()
	if err == nil {
		t.Fatal("expected error for space with newline-only predicate, got nil")
	}
}

func TestDecoder_SkipBytes_CustomPredicate_SkipDigits(t *testing.T) {
	// Unusual but valid: skip digit bytes before the length field
	// This tests that predicates are truly arbitrary
	skipZeros := func(b byte) bool { return b == '0' }
	dec := NewDecoder(bytes.NewReader([]byte("005:hello,05:world,")), SkipBytes(skipZeros))

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	data, err = dec.Decode()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("second: got %q, want %q", string(data), "world")
	}
}

func TestDecoder_SkipBytes_EmptyStream(t *testing.T) {
	// Empty stream should return EOF regardless of predicate
	dec := NewDecoder(bytes.NewReader([]byte{}), SkipASCIIWhitespace())

	_, err := dec.Decode()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestDecoder_SkipBytes_OnlyWhitespace(t *testing.T) {
	// Stream with only whitespace should eventually hit EOF
	dec := NewDecoder(bytes.NewReader([]byte("   \n\t\r  ")), SkipASCIIWhitespace())

	_, err := dec.Decode()
	if err != io.EOF {
		t.Errorf("expected io.EOF for stream with only whitespace, got %v", err)
	}
}

func TestDecoder_SkipBytes_PreservesPayloadBytes(t *testing.T) {
	// Bytes matching predicate should NEVER be skipped from payload
	skipNewlines := func(b byte) bool { return b == '\n' }
	dec := NewDecoder(bytes.NewReader([]byte("13:hello\nworld\n\n,")), SkipBytes(skipNewlines))

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(data) != "hello\nworld\n\n" {
		t.Errorf("payload newlines not preserved, got %q", string(data))
	}
}

func TestDecoder_SkipBytes_CustomPredicate_Keyed(t *testing.T) {
	// Test that predicates work with keyed netstrings too
	skipNewlines := func(b byte) bool { return b == '\n' }
	dec := NewDecoder(bytes.NewReader([]byte("6:ttoken,\n9:smy-state,")), SkipBytes(skipNewlines))

	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if key != 't' || string(value) != "token" {
		t.Errorf("first: got key=%q value=%q", key, string(value))
	}

	key, value, err = dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if key != 's' || string(value) != "my-state" {
		t.Errorf("second: got key=%q value=%q", key, string(value))
	}
}
