package netstr

const (
	// Default maximum netstring length (1MB)
	defaultMaxLength = 1024 * 1024
)

// config holds decoder configuration.
type config struct {
	lenient   bool
	maxLength int
}

// Option configures a Decoder.
type Option func(*config)

// Lenient enables tolerance for whitespace between netstrings.
// Whitespace (space, tab, \n, \r) is skipped before the length digits.
// Whitespace inside the payload is always preserved.
//
// This is useful for debugging auth plugins that use echo or println,
// which add trailing newlines.
//
// Default: false (strict mode - any whitespace causes an error)
func Lenient() Option {
	return func(c *config) {
		c.lenient = true
	}
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
