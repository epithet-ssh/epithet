package netstr

import (
	"fmt"
	"io"
)

// Decode reads the next standard netstring (no key) and returns its payload.
//
// Returns io.EOF when the stream ends.
func (d *Decoder) Decode() ([]byte, error) {
	// Read length
	length, err := d.readLength()
	if err != nil {
		return nil, err
	}

	// Read payload (all bytes)
	payload, err := d.readExact(length)
	if err != nil {
		return nil, err
	}

	// Expect comma
	if err := d.expectComma(); err != nil {
		return nil, err
	}

	return payload, nil
}

// DecodeKeyed reads the next keyed netstring and returns its key and payload.
//
// The first byte of the netstring is the key, and the remaining bytes are the payload.
// Returns io.EOF when the stream ends.
func (d *Decoder) DecodeKeyed() (key byte, value []byte, err error) {
	// Read length
	length, err := d.readLength()
	if err != nil {
		return 0, nil, err
	}

	// Length must be at least 1 (for the key)
	if length < 1 {
		return 0, nil, &FormatError{
			Offset: d.offset,
			Reason: "keyed netstring must have length >= 1",
		}
	}

	// Read key byte
	key, err = d.readByte()
	if err != nil {
		return 0, nil, err
	}

	// Read payload (length-1 bytes, since key is 1 byte)
	payload, err := d.readExact(length - 1)
	if err != nil {
		return 0, nil, err
	}

	// Expect comma
	if err := d.expectComma(); err != nil {
		return 0, nil, err
	}

	return key, payload, nil
}

// readLength reads the length field from the netstring.
// Format: [whitespace] <digits> ':'
//
// In lenient mode, skips leading whitespace before the first digit.
// Returns the parsed length as an integer.
func (d *Decoder) readLength() (int, error) {
	length := 0
	digitCount := 0
	firstByte := true

	for {
		b, err := d.readByte()
		if err != nil {
			return 0, err
		}

		// Skip leading whitespace in lenient mode (before any digits)
		if d.lenient && firstByte && isWhitespace(b) {
			continue // Keep looking for first digit
		}

		firstByte = false

		// Check for end of length field
		if b == ':' {
			if digitCount == 0 {
				return 0, &FormatError{
					Offset: d.offset,
					Reason: "length field is empty",
				}
			}
			return length, nil
		}

		// Must be a digit
		if b < '0' || b > '9' {
			if isWhitespace(b) {
				return 0, &FormatError{
					Offset: d.offset,
					Reason: fmt.Sprintf("unexpected whitespace in length field (use netstr.Lenient() for whitespace tolerance)"),
				}
			}
			return 0, &FormatError{
				Offset: d.offset,
				Reason: fmt.Sprintf("expected digit or ':', got %q", rune(b)),
			}
		}

		digit := int(b - '0')
		digitCount++

		// Reject leading zeros (except "0:")
		if length == 0 && digit == 0 && digitCount == 1 {
			// Peek ahead to see if this is "0:" (valid) or "0<digit>" (invalid)
			next, err := d.readByte()
			if err != nil {
				return 0, err
			}
			if next == ':' {
				// Valid "0:" case
				return 0, nil
			}
			if next >= '0' && next <= '9' {
				return 0, &FormatError{
					Offset: d.offset,
					Reason: "length field has leading zero",
				}
			}
			// Something else after '0' - invalid format
			return 0, &FormatError{
				Offset: d.offset,
				Reason: fmt.Sprintf("expected ':' after '0', got %q", rune(next)),
			}
		}

		// Accumulate digit
		length = length*10 + digit

		// Check against max length
		if length > d.maxLength {
			return 0, ErrTooLarge
		}
	}
}

// readExact reads exactly n bytes from the stream.
func (d *Decoder) readExact(n int) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}

	payload := make([]byte, n)
	for i := 0; i < n; i++ {
		b, err := d.readByte()
		if err != nil {
			if err == io.EOF {
				return nil, &FormatError{
					Offset: d.offset,
					Reason: fmt.Sprintf("unexpected EOF: expected %d bytes, got %d", n, i),
				}
			}
			return nil, err
		}
		payload[i] = b
	}
	return payload, nil
}

// expectComma reads a byte and verifies it's a comma.
func (d *Decoder) expectComma() error {
	b, err := d.readByte()
	if err != nil {
		if err == io.EOF {
			return &FormatError{
				Offset: d.offset,
				Reason: "unexpected EOF: expected ','",
			}
		}
		return err
	}
	if b != ',' {
		return &FormatError{
			Offset: d.offset,
			Reason: fmt.Sprintf("expected ',', got %q", rune(b)),
		}
	}
	return nil
}

// readByte reads a single byte and tracks position for error reporting.
func (d *Decoder) readByte() (byte, error) {
	b, err := d.r.ReadByte()
	if err == nil {
		d.offset++
	}
	return b, err
}

// isWhitespace returns true if b is a whitespace character.
// Whitespace is defined as: space, tab, \n, \r
func isWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
