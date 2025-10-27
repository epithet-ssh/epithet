package netstr

import "unicode"

const (
	// Default maximum netstring length (1MB)
	defaultMaxLength = 1024 * 1024
)

// SkipPredicate determines whether a byte should be skipped before parsing a netstring.
// The predicate is called for each byte before the length digits.
// Return true to skip the byte, false to process it.
//
// Note: Since netstrings are a binary protocol and parsing is byte-oriented,
// multi-byte UTF-8 sequences cannot be properly handled. Custom predicates
// operate on individual bytes.
type SkipPredicate func(byte) bool

// config holds decoder configuration.
type config struct {
	skipPredicate SkipPredicate
	maxLength     int
}

// Option configures a Decoder.
type Option func(*config)

// Built-in skip predicates
var (
	skipNone = func(byte) bool { return false }

	// skipASCIIWhitespace uses unicode.IsSpace but restricts to ASCII range (bytes < 128).
	// This includes: space, tab, \n, \r, \v, \f
	skipASCIIWhitespace = func(b byte) bool {
		return b < 128 && unicode.IsSpace(rune(b))
	}

	// skipUnicodeWhitespace uses unicode.IsSpace without restriction.
	// This includes ASCII whitespace plus some non-ASCII bytes like 0x85 (NEL), 0xA0 (NBSP).
	// Note: Since we parse byte-by-byte, multi-byte UTF-8 sequences won't be detected.
	skipUnicodeWhitespace = func(b byte) bool {
		return unicode.IsSpace(rune(b))
	}
)

// SkipNone configures the decoder to use strict mode - no bytes are skipped.
// This is the default behavior.
//
// Any whitespace between netstrings will cause a format error.
func SkipNone() Option {
	return func(c *config) {
		c.skipPredicate = skipNone
	}
}

// SkipASCIIWhitespace configures the decoder to skip ASCII whitespace bytes
// before the length digits. Uses unicode.IsSpace() restricted to ASCII range (< 128).
//
// This includes: space, tab, \n (LF), \r (CR), \v (VT), \f (FF).
//
// This is useful for debugging auth plugins that use echo or println,
// which add trailing newlines.
//
// Whitespace inside the netstring payload is always preserved.
func SkipASCIIWhitespace() Option {
	return func(c *config) {
		c.skipPredicate = skipASCIIWhitespace
	}
}

// SkipUnicodeWhitespace configures the decoder to skip whitespace bytes as defined
// by unicode.IsSpace(). This includes ASCII whitespace plus some non-ASCII bytes
// like 0x85 (NEL) and 0xA0 (NBSP).
//
// Note: Since netstrings are parsed byte-by-byte, multi-byte UTF-8 sequences
// cannot be properly detected. This option works on individual bytes only.
func SkipUnicodeWhitespace() Option {
	return func(c *config) {
		c.skipPredicate = skipUnicodeWhitespace
	}
}

// SkipExtendedWhitespace is deprecated. Use SkipASCIIWhitespace() instead,
// which now includes all ASCII whitespace characters (including \v and \f)
// using unicode.IsSpace().
//
// Deprecated: Use SkipASCIIWhitespace() or SkipUnicodeWhitespace().
func SkipExtendedWhitespace() Option {
	return SkipASCIIWhitespace()
}

// SkipBytes configures the decoder with a custom skip predicate.
// The predicate is called for each byte before the length digits.
// Return true to skip the byte, false to process it normally.
//
// Example - skip only newlines:
//
//	pred := func(b byte) bool { return b == '\n' }
//	dec := netstr.NewDecoder(r, netstr.SkipBytes(pred))
//
// Note: The predicate operates on individual bytes. Multi-byte UTF-8
// sequences cannot be properly detected in a zero-lookahead byte-by-byte parser.
func SkipBytes(pred SkipPredicate) Option {
	return func(c *config) {
		c.skipPredicate = pred
	}
}

// Lenient is an alias for SkipASCIIWhitespace for backward compatibility.
//
// Deprecated: Use SkipASCIIWhitespace() for clarity.
func Lenient() Option {
	return SkipASCIIWhitespace()
}

// MaxLength sets the maximum allowed netstring length in bytes.
// Netstrings with length fields exceeding this value will return ErrTooLarge.
//
// This prevents memory exhaustion attacks from malicious inputs.
//
// Default: 1MB (1048576 bytes)
func MaxLength(n int) Option {
	return func(c *config) {
		c.maxLength = n
	}
}
