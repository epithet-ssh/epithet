package main

import (
	"fmt"

	"github.com/gobwas/glob"
)

type Config struct {
	Match []Match `toml:"match"`
	CaUrl string  `toml:"ca_url"`
}

// Match wraps a glob.Glob pattern for TOML unmarshaling
type Match struct {
	glob.Glob
}

// UnmarshalText implements the encoding.TextUnmarshaler interface for go-toml/v2.
// It parses a string value and compiles it into a glob pattern.
func (m *Match) UnmarshalText(text []byte) error {
	pattern := string(text)

	g, err := glob.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
	}

	m.Glob = g
	return nil
}
