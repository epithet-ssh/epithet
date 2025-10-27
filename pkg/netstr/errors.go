package netstr

import (
	"errors"
	"fmt"
)

// Sentinel errors
var (
	// ErrInvalidFormat indicates a malformed netstring.
	ErrInvalidFormat = errors.New("netstr: invalid format")

	// ErrTooLarge indicates a netstring length exceeds the configured maximum.
	ErrTooLarge = errors.New("netstr: length exceeds maximum")
)

// FormatError provides detailed information about a parsing error.
type FormatError struct {
	Offset int    // Approximate byte offset where error occurred
	Reason string // Human-readable explanation
}

func (e *FormatError) Error() string {
	return fmt.Sprintf("netstr: format error at offset %d: %s", e.Offset, e.Reason)
}

func (e *FormatError) Unwrap() error {
	return ErrInvalidFormat
}
