package netstr

import (
	"bytes"
	"io"
	"testing"
	"testing/quick"
)

// Property: encode(x) -> decode() == x (round-trip)
func TestProperty_RoundTrip(t *testing.T) {
	property := func(data []byte) bool {
		var buf bytes.Buffer
		enc := NewEncoder(&buf)

		if err := enc.Encode(data); err != nil {
			t.Logf("encode failed: %v", err)
			return false
		}

		dec := NewDecoder(bytes.NewReader(buf.Bytes()))
		decoded, err := dec.Decode()
		if err != nil {
			t.Logf("decode failed: %v", err)
			return false
		}

		return bytes.Equal(decoded, data)
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: encodeKeyed(k, x) -> decodeKeyed() == (k, x)
func TestProperty_RoundTripKeyed(t *testing.T) {
	property := func(key byte, data []byte) bool {
		var buf bytes.Buffer
		enc := NewEncoder(&buf)

		if err := enc.EncodeKeyed(key, data); err != nil {
			t.Logf("encode failed: %v", err)
			return false
		}

		dec := NewDecoder(bytes.NewReader(buf.Bytes()))
		decodedKey, decodedValue, err := dec.DecodeKeyed()
		if err != nil {
			t.Logf("decode failed: %v", err)
			return false
		}

		return decodedKey == key && bytes.Equal(decodedValue, data)
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Length is preserved through round-trip
func TestProperty_LengthPreservation(t *testing.T) {
	property := func(data []byte) bool {
		var buf bytes.Buffer
		enc := NewEncoder(&buf)
		enc.Encode(data)

		dec := NewDecoder(bytes.NewReader(buf.Bytes()))
		decoded, err := dec.Decode()
		if err != nil {
			return false
		}

		return len(decoded) == len(data)
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Concatenation - encode(a) + encode(b) decodes to a, then b
func TestProperty_Concatenation(t *testing.T) {
	property := func(data1, data2 []byte) bool {
		var buf bytes.Buffer
		enc := NewEncoder(&buf)

		if err := enc.Encode(data1); err != nil {
			return false
		}
		if err := enc.Encode(data2); err != nil {
			return false
		}

		dec := NewDecoder(bytes.NewReader(buf.Bytes()))

		decoded1, err := dec.Decode()
		if err != nil {
			return false
		}

		decoded2, err := dec.Decode()
		if err != nil {
			return false
		}

		return bytes.Equal(decoded1, data1) && bytes.Equal(decoded2, data2)
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Multiple encodes in sequence can all be decoded
func TestProperty_MultipleRoundTrips(t *testing.T) {
	property := func(items [][]byte) bool {
		if len(items) == 0 {
			return true // Vacuously true
		}

		var buf bytes.Buffer
		enc := NewEncoder(&buf)

		// Encode all items
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				return false
			}
		}

		// Decode all items
		dec := NewDecoder(bytes.NewReader(buf.Bytes()))
		for i, original := range items {
			decoded, err := dec.Decode()
			if err != nil {
				t.Logf("decode %d failed: %v", i, err)
				return false
			}
			if !bytes.Equal(decoded, original) {
				t.Logf("item %d mismatch", i)
				return false
			}
		}

		// Should be EOF now
		_, err := dec.Decode()
		return err == io.EOF
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Lenient and strict modes produce same result for valid input
func TestProperty_LenientStrictEquivalence(t *testing.T) {
	property := func(data []byte) bool {
		var buf bytes.Buffer
		enc := NewEncoder(&buf)
		enc.Encode(data)

		// Decode in strict mode
		decStrict := NewDecoder(bytes.NewReader(buf.Bytes()))
		strictResult, err := decStrict.Decode()
		if err != nil {
			return false
		}

		// Decode in lenient mode
		decLenient := NewDecoder(bytes.NewReader(buf.Bytes()), Lenient())
		lenientResult, err := decLenient.Decode()
		if err != nil {
			return false
		}

		return bytes.Equal(strictResult, lenientResult)
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Adding newline between netstrings works in lenient mode
func TestProperty_LenientWhitespace(t *testing.T) {
	property := func(data1, data2 []byte) bool {
		var buf bytes.Buffer
		enc := NewEncoder(&buf)

		enc.Encode(data1)
		buf.WriteByte('\n') // Add whitespace between
		enc.Encode(data2)

		// Lenient mode should handle the newline
		dec := NewDecoder(bytes.NewReader(buf.Bytes()), Lenient())

		decoded1, err := dec.Decode()
		if err != nil {
			return false
		}

		decoded2, err := dec.Decode()
		if err != nil {
			return false
		}

		return bytes.Equal(decoded1, data1) && bytes.Equal(decoded2, data2)
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Binary safety - all byte values are preserved
func TestProperty_BinarySafety(t *testing.T) {
	property := func(data []byte) bool {
		// Ensure we test all byte values by including them explicitly
		testData := make([]byte, len(data)+256)
		copy(testData, data)
		for i := 0; i < 256; i++ {
			testData[len(data)+i] = byte(i)
		}

		var buf bytes.Buffer
		enc := NewEncoder(&buf)
		enc.Encode(testData)

		dec := NewDecoder(bytes.NewReader(buf.Bytes()))
		decoded, err := dec.Decode()
		if err != nil {
			return false
		}

		return bytes.Equal(decoded, testData)
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Empty data round-trips correctly
func TestProperty_EmptyRoundTrip(t *testing.T) {
	property := func() bool {
		var buf bytes.Buffer
		enc := NewEncoder(&buf)
		enc.Encode([]byte{})

		dec := NewDecoder(bytes.NewReader(buf.Bytes()))
		decoded, err := dec.Decode()
		if err != nil {
			return false
		}

		return len(decoded) == 0
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Keyed netstrings maintain key-value association
func TestProperty_KeyedAssociation(t *testing.T) {
	type keyValue struct {
		Key   byte
		Value []byte
	}

	property := func(items []keyValue) bool {
		if len(items) == 0 {
			return true
		}

		var buf bytes.Buffer
		enc := NewEncoder(&buf)

		// Encode all key-value pairs
		for _, item := range items {
			if err := enc.EncodeKeyed(item.Key, item.Value); err != nil {
				return false
			}
		}

		// Decode and verify
		dec := NewDecoder(bytes.NewReader(buf.Bytes()))
		for i, original := range items {
			key, value, err := dec.DecodeKeyed()
			if err != nil {
				t.Logf("decode %d failed: %v", i, err)
				return false
			}
			if key != original.Key || !bytes.Equal(value, original.Value) {
				t.Logf("item %d mismatch: got key=%q val=%q, want key=%q val=%q",
					i, key, value, original.Key, original.Value)
				return false
			}
		}

		return true
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: Decode fails with incomplete data
func TestProperty_IncompleteDataFails(t *testing.T) {
	property := func(data []byte) bool {
		if len(data) == 0 {
			return true // Can't truncate empty data
		}

		var buf bytes.Buffer
		enc := NewEncoder(&buf)
		enc.Encode(data)

		// Truncate the encoded data (remove last byte)
		encoded := buf.Bytes()
		if len(encoded) == 0 {
			return true
		}
		truncated := encoded[:len(encoded)-1]

		// Decoding truncated data should fail
		dec := NewDecoder(bytes.NewReader(truncated))
		_, err := dec.Decode()

		return err != nil // We expect an error
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}

// Property: MaxLength enforcement
func TestProperty_MaxLengthEnforcement(t *testing.T) {
	property := func(data []byte) bool {
		// Skip if data is small enough
		if len(data) <= 100 {
			return true
		}

		var buf bytes.Buffer
		enc := NewEncoder(&buf)
		enc.Encode(data)

		// Decode with MaxLength smaller than data
		dec := NewDecoder(bytes.NewReader(buf.Bytes()), MaxLength(100))
		_, err := dec.Decode()

		// Should fail with ErrTooLarge
		return err == ErrTooLarge
	}

	if err := quick.Check(property, nil); err != nil {
		t.Error(err)
	}
}
