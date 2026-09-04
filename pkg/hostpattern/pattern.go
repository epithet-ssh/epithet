// Package hostpattern implements the hostname-pattern language shared by
// inventory resolution and Writ host selectors.
package hostpattern

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Pattern is a validated, anchored hostname pattern. Dots are label
// separators: * and ? stay within one label, while ** is legal only as a
// complete label and crosses zero or more labels.
type Pattern struct {
	raw  string
	path string
	any  bool
}

// Parse validates raw against Epithet's deliberately small hostname-pattern
// language. In particular, it rejects the additional syntax understood by the
// doublestar matching engine so a dependency change cannot silently broaden a
// policy or inventory entry.
func Parse(raw string) (Pattern, error) {
	if raw == "" {
		return Pattern{}, fmt.Errorf("hostname pattern is empty")
	}
	for _, r := range raw {
		switch r {
		case '{', '}', '[', ']', '\\', '/':
			return Pattern{}, fmt.Errorf("hostname pattern %q contains unsupported character %q; only literals, *, ?, and whole-label ** are supported", raw, r)
		}
	}
	for _, label := range strings.Split(raw, ".") {
		for i := 0; i < len(label); {
			if label[i] != '*' {
				i++
				continue
			}
			end := i + 1
			for end < len(label) && label[end] == '*' {
				end++
			}
			stars := end - i
			switch {
			case stars > 2:
				return Pattern{}, fmt.Errorf("hostname pattern %q contains a run of %d stars; use * within a label or ** as a complete label", raw, stars)
			case stars == 2 && label != "**":
				return Pattern{}, fmt.Errorf("hostname pattern %q uses ** inside label %q; ** must be a complete label", raw, label)
			}
			i = end
		}
	}

	pathPattern := strings.ReplaceAll(raw, ".", "/")
	if !doublestar.ValidatePattern(pathPattern) {
		return Pattern{}, fmt.Errorf("invalid hostname pattern %q", raw)
	}
	return Pattern{raw: raw, path: pathPattern, any: raw == "*"}, nil
}

// String returns the pattern as authored.
func (p Pattern) String() string {
	return p.raw
}

// Match reports whether name matches the complete pattern. A slash is never a
// valid hostname label character here because it is the internal separator
// used to give doublestar DNS-label semantics.
func (p Pattern) Match(name string) bool {
	if name == "" || strings.ContainsRune(name, '/') {
		return false
	}
	if p.any {
		return true
	}
	return doublestar.MatchUnvalidated(p.path, strings.ReplaceAll(name, ".", "/"))
}

// Match validates raw and matches name. It is intended for compiled policy
// values; malformed patterns fail closed.
func Match(raw, name string) bool {
	p, err := Parse(raw)
	return err == nil && p.Match(name)
}
