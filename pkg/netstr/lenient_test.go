package netstr

import (
	"bytes"
	"testing"
)

func TestDecoder_Lenient_Space(t *testing.T) {
	// Lenient mode should skip spaces before length
	dec := NewDecoder(bytes.NewReader([]byte("5:hello, 5:world,")), Lenient())

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

func TestDecoder_Lenient_Tab(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\t5:world,")), Lenient())

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

func TestDecoder_Lenient_Newline(t *testing.T) {
	// Simulates output from: printf "5:hello,\n6:ttoken,"
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\n6:ttoken,")), Lenient())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if key != 't' {
		t.Errorf("got key %q, want 't'", key)
	}
	if string(value) != "token" {
		t.Errorf("got value %q, want %q", string(value), "token")
	}
}

func TestDecoder_Lenient_CarriageReturn(t *testing.T) {
	dec := NewDecoder(bytes.NewReader([]byte("5:hello,\r6:ttoken,")), Lenient())

	_, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}

	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if key != 't' || string(value) != "token" {
		t.Errorf("got key=%q value=%q", key, string(value))
	}
}

func TestDecoder_Lenient_MixedWhitespace(t *testing.T) {
	// Multiple types of whitespace
	dec := NewDecoder(bytes.NewReader([]byte("5:hello, \t\n\r6:ttoken,")), Lenient())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("first: got %q, want %q", string(data), "hello")
	}

	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if key != 't' || string(value) != "token" {
		t.Errorf("got key=%q value=%q", key, string(value))
	}
}

func TestDecoder_Lenient_LeadingWhitespace(t *testing.T) {
	// Whitespace at the very start (before first netstring)
	dec := NewDecoder(bytes.NewReader([]byte("\n  \t5:hello,")), Lenient())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q, want %q", string(data), "hello")
	}
}

func TestDecoder_Lenient_PreservesPayloadWhitespace(t *testing.T) {
	// Whitespace inside the payload should NEVER be skipped, even in lenient mode
	dec := NewDecoder(bytes.NewReader([]byte("11:hello world,")), Lenient())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("payload whitespace not preserved, got %q", string(data))
	}
}

func TestDecoder_Lenient_EchoSimulation(t *testing.T) {
	// Simulate bash auth plugin using echo (adds trailing newline)
	// echo "6:ttoken," outputs "6:ttoken,\n"
	dec := NewDecoder(bytes.NewReader([]byte("6:ttoken,\n")), Lenient())

	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if key != 't' || string(value) != "token" {
		t.Errorf("got key=%q value=%q, want key='t' value='token'", key, string(value))
	}
}

func TestDecoder_Lenient_PrintfNoNewline(t *testing.T) {
	// Simulate bash auth plugin using printf '%s' (no trailing newline)
	// This should work in both strict and lenient mode
	dec := NewDecoder(bytes.NewReader([]byte("6:ttoken,")), Lenient())

	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if key != 't' || string(value) != "token" {
		t.Errorf("got key=%q value=%q, want key='t' value='token'", key, string(value))
	}
}

func TestDecoder_Lenient_MultipleNewlines(t *testing.T) {
	// Multiple echo statements: echo "..."; echo "..."
	input := "12:tfirst-token,\n16:s{\"refresh\":\"a\"},\n"
	dec := NewDecoder(bytes.NewReader([]byte(input)), Lenient())

	key1, value1, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("first decode failed: %v", err)
	}
	if key1 != 't' || string(value1) != "first-token" {
		t.Errorf("first: got key=%q value=%q", key1, string(value1))
	}

	key2, value2, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("second decode failed: %v", err)
	}
	if key2 != 's' || string(value2) != `{"refresh":"a"}` {
		t.Errorf("second: got key=%q value=%q", key2, string(value2))
	}
}

func TestDecoder_Lenient_WhitespaceInLengthRejected(t *testing.T) {
	// Whitespace WITHIN the length field should be rejected
	// (only leading whitespace is tolerated)
	dec := NewDecoder(bytes.NewReader([]byte("5 :hello,")), Lenient())

	_, err := dec.Decode()
	if err == nil {
		t.Fatal("expected error for whitespace within length field, got nil")
	}
}

func TestDecoder_Lenient_NewlineInPayload(t *testing.T) {
	// Newlines inside payload should be preserved
	dec := NewDecoder(bytes.NewReader([]byte("13:hello\nworld\n\n,")), Lenient())

	data, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(data) != "hello\nworld\n\n" {
		t.Errorf("newlines in payload not preserved, got %q", string(data))
	}
}
