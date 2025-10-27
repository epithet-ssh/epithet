package netstr

import "io"

// Decoder reads netstrings from an io.ByteReader.
//
// io.ByteReader is implemented by *bufio.Reader and *bytes.Reader.
// For network streams, wrap your io.Reader in bufio.Reader for buffering:
//
//	dec := netstr.NewDecoder(bufio.NewReader(conn))
//
// The decoder uses zero lookahead - every byte read is immediately processed.
type Decoder struct {
	r             io.ByteReader
	skipPredicate SkipPredicate
	maxLength     int
	offset        int // Track position for error reporting
}

// NewDecoder creates a new netstring decoder.
//
// The decoder reads from r, which must implement io.ByteReader.
// Optional configuration can be provided via Option functions.
//
// Example:
//
//	dec := netstr.NewDecoder(bufio.NewReader(conn), netstr.SkipASCIIWhitespace())
func NewDecoder(r io.ByteReader, opts ...Option) *Decoder {
	cfg := &config{
		skipPredicate: nil, // nil means skip nothing (strict mode)
		maxLength:     defaultMaxLength,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Decoder{
		r:             r,
		skipPredicate: cfg.skipPredicate,
		maxLength:     cfg.maxLength,
		offset:        0,
	}
}

// Encoder writes netstrings to an io.Writer.
//
// The encoder writes are unbuffered. For network streams,
// wrap your io.Writer in bufio.Writer if buffering is desired:
//
//	enc := netstr.NewEncoder(bufio.NewWriter(conn))
type Encoder struct {
	w io.Writer
}

// NewEncoder creates a new netstring encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}
