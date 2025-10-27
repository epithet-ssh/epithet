// Package netstr implements encoding and decoding of netstrings.
//
// Netstrings are a simple, self-delimiting binary protocol for encoding
// byte sequences. The format is: <length>:<payload>,
//
// Where <length> is the decimal ASCII representation of the payload length,
// followed by a colon, the payload bytes, and a terminating comma.
//
// # Examples
//
// Standard netstring:
//
//	"5:hello,"  // encodes the 5-byte string "hello"
//	"0:,"       // encodes an empty payload
//
// Keyed netstring (first byte is the key):
//
//	"6:nBrian," // key='n', value="Brian"
//	"11:tmy-token," // key='t', value="my-token"
//
// # Basic Usage
//
// Encoding:
//
//	var buf bytes.Buffer
//	enc := netstr.NewEncoder(&buf)
//	enc.Encode([]byte("hello"))          // writes "5:hello,"
//	enc.EncodeKeyed('t', []byte("token")) // writes "6:ttoken,"
//
// Decoding (strict mode):
//
//	dec := netstr.NewDecoder(bytes.NewReader(data))
//	payload, err := dec.Decode()
//	key, value, err := dec.DecodeKeyed()
//
// Decoding (lenient mode - tolerates whitespace):
//
//	// For debugging auth plugins that use echo/println
//	dec := netstr.NewDecoder(bufio.NewReader(conn), netstr.Lenient())
//	key, value, err := dec.DecodeKeyed()
//
// # Design Principles
//
// This library is designed for composability:
//
//   - No internal buffering: Decoder uses io.ByteReader, Encoder uses io.Writer
//   - Users control buffering: wrap streams in bufio.Reader/Writer as needed
//   - Zero lookahead: every byte is immediately processed
//   - Simple interfaces: stdlib types only
//
// # Lenient Mode
//
// By default, netstrings must be strictly formatted with no whitespace between them.
// Lenient mode allows whitespace (space, tab, \n, \r) to appear before the length digits,
// making it easier to debug producers that use echo or println statements.
//
// Whitespace inside the payload is always preserved - it's only skipped between netstrings.
//
// # Security
//
// The MaxLength option (default 1MB) prevents memory exhaustion attacks from
// malicious inputs with very large length fields.
package netstr
