package netstr

import (
	"bytes"
	"testing"
)

func TestRoundTrip_Simple(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	original := []byte("hello world")
	if err := enc.Encode(original); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	dec := NewDecoder(bytes.NewReader(buf.Bytes()))
	decoded, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("roundtrip failed: got %q, want %q", decoded, original)
	}
}

func TestRoundTrip_Empty(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	original := []byte{}
	if err := enc.Encode(original); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	dec := NewDecoder(bytes.NewReader(buf.Bytes()))
	decoded, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("expected empty, got %d bytes", len(decoded))
	}
}

func TestRoundTrip_Binary(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// All possible byte values
	original := make([]byte, 256)
	for i := range original {
		original[i] = byte(i)
	}

	if err := enc.Encode(original); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	dec := NewDecoder(bytes.NewReader(buf.Bytes()))
	decoded, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("roundtrip failed for binary data")
	}
}

func TestRoundTrip_Keyed(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	originalKey := byte('t')
	originalValue := []byte("my-token-value")

	if err := enc.EncodeKeyed(originalKey, originalValue); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	dec := NewDecoder(bytes.NewReader(buf.Bytes()))
	key, value, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if key != originalKey {
		t.Errorf("key mismatch: got %q, want %q", key, originalKey)
	}
	if !bytes.Equal(value, originalValue) {
		t.Errorf("value mismatch: got %q, want %q", value, originalValue)
	}
}

func TestRoundTrip_Multiple(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Encode multiple netstrings
	data1 := []byte("first")
	data2 := []byte("second")
	data3 := []byte("third")

	if err := enc.Encode(data1); err != nil {
		t.Fatalf("encode 1 failed: %v", err)
	}
	if err := enc.Encode(data2); err != nil {
		t.Fatalf("encode 2 failed: %v", err)
	}
	if err := enc.Encode(data3); err != nil {
		t.Fatalf("encode 3 failed: %v", err)
	}

	// Decode them back
	dec := NewDecoder(bytes.NewReader(buf.Bytes()))

	decoded1, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode 1 failed: %v", err)
	}
	if !bytes.Equal(decoded1, data1) {
		t.Errorf("decode 1 mismatch: got %q, want %q", decoded1, data1)
	}

	decoded2, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode 2 failed: %v", err)
	}
	if !bytes.Equal(decoded2, data2) {
		t.Errorf("decode 2 mismatch: got %q, want %q", decoded2, data2)
	}

	decoded3, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode 3 failed: %v", err)
	}
	if !bytes.Equal(decoded3, data3) {
		t.Errorf("decode 3 mismatch: got %q, want %q", decoded3, data3)
	}
}

func TestRoundTrip_MultipleKeyed(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Simulate auth protocol: token + state
	if err := enc.EncodeKeyed('t', []byte("access-token-xyz")); err != nil {
		t.Fatalf("encode token failed: %v", err)
	}
	if err := enc.EncodeKeyed('s', []byte(`{"refresh":"abc","exp":1234}`)); err != nil {
		t.Fatalf("encode state failed: %v", err)
	}

	// Decode them back
	dec := NewDecoder(bytes.NewReader(buf.Bytes()))

	key1, value1, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("decode token failed: %v", err)
	}
	if key1 != 't' || string(value1) != "access-token-xyz" {
		t.Errorf("token mismatch: got key=%q value=%q", key1, value1)
	}

	key2, value2, err := dec.DecodeKeyed()
	if err != nil {
		t.Fatalf("decode state failed: %v", err)
	}
	if key2 != 's' || string(value2) != `{"refresh":"abc","exp":1234}` {
		t.Errorf("state mismatch: got key=%q value=%q", key2, value2)
	}
}

func TestRoundTrip_LargePayload(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// 10KB of data
	original := bytes.Repeat([]byte("abcdefghij"), 1000)

	if err := enc.Encode(original); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	dec := NewDecoder(bytes.NewReader(buf.Bytes()))
	decoded, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("large payload roundtrip failed")
	}
}

func TestRoundTrip_SpecialCharacters(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Data with characters that have special meaning in netstring format
	original := []byte("0:,123:hello,")

	if err := enc.Encode(original); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	dec := NewDecoder(bytes.NewReader(buf.Bytes()))
	decoded, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("special characters not preserved: got %q, want %q", decoded, original)
	}
}

func TestRoundTrip_Unicode(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	original := []byte("Hello 世界 🌍 Привет")

	if err := enc.Encode(original); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	dec := NewDecoder(bytes.NewReader(buf.Bytes()))
	decoded, err := dec.Decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("unicode not preserved: got %q, want %q", decoded, original)
	}
}
