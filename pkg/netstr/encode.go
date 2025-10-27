package netstr

import (
	"fmt"
)

// Encode writes a standard netstring (no key) containing data.
//
// The netstring format is: <length>:<data>,
//
// Example:
//
//	enc.Encode([]byte("hello")) // writes "5:hello,"
func (e *Encoder) Encode(data []byte) error {
	// Format: <length>:<data>,
	netstring := fmt.Appendf(nil, "%d:", len(data))
	netstring = append(netstring, data...)
	netstring = append(netstring, ',')

	_, err := e.w.Write(netstring)
	return err
}

// EncodeKeyed writes a keyed netstring with the given key and data.
//
// The key is prepended to the data as the first byte of the payload.
// The netstring format is: <length>:<key><data>,
//
// Example:
//
//	enc.EncodeKeyed('t', []byte("token")) // writes "6:ttoken,"
func (e *Encoder) EncodeKeyed(key byte, data []byte) error {
	// Format: <length>:<key><data>,
	// Length is 1 (key) + len(data)
	length := 1 + len(data)

	netstring := fmt.Appendf(nil, "%d:", length)
	netstring = append(netstring, key)
	netstring = append(netstring, data...)
	netstring = append(netstring, ',')

	_, err := e.w.Write(netstring)
	return err
}

// EncodeString is a convenience method that encodes a string as a standard netstring.
func (e *Encoder) EncodeString(s string) error {
	return e.Encode([]byte(s))
}

// EncodeKeyedString is a convenience method that encodes a string as a keyed netstring.
func (e *Encoder) EncodeKeyedString(key byte, s string) error {
	return e.EncodeKeyed(key, []byte(s))
}
