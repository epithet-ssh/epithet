package parser

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// Token validators, ported from the reference implementation.
// Timestamps and durations are ordinary tokens validated after parsing,
// not lexer modes (SPEC §3).

// maxDurationSeconds bounds a writ duration to what fits in a
// time.Duration (about 292 years), so downstream conversion to
// nanoseconds can never overflow.
const maxDurationSeconds = uint64(math.MaxInt64 / int64(time.Second))

// ParseDuration parses a writ duration — integer plus s/m/h parts,
// composable: 2m, 90s, 1h30m — returning whole seconds. Zero is
// rejected: the IL uses zero as its "no ttl set" sentinel, and a
// zero-lifetime certificate is never what an author meant.
func ParseDuration(s string) (uint64, error) {
	var total uint64
	num := ""
	any := false
	tooLarge := func() (uint64, error) {
		return 0, fmt.Errorf("invalid duration `%s` — too large", s)
	}
	for _, c := range s {
		if c >= '0' && c <= '9' {
			num += string(c)
			continue
		}
		var mult uint64
		switch c {
		case 's':
			mult = 1
		case 'm':
			mult = 60
		case 'h':
			mult = 3600
		default:
			return 0, fmt.Errorf("invalid duration `%s` — use integer s/m/h parts like 2m, 90s, 1h30m", s)
		}
		if num == "" {
			return 0, fmt.Errorf("invalid duration `%s` — unit `%c` has no number", s, c)
		}
		n, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			return tooLarge()
		}
		if n > maxDurationSeconds/mult {
			return tooLarge()
		}
		part := n * mult
		if total > maxDurationSeconds-part {
			return tooLarge()
		}
		total += part
		num = ""
		any = true
	}
	if num != "" {
		return 0, fmt.Errorf("invalid duration `%s` — trailing number without a unit", s)
	}
	if !any {
		return 0, fmt.Errorf("invalid duration `%s`", s)
	}
	if total == 0 {
		return 0, fmt.Errorf("invalid duration `%s` — must be positive", s)
	}
	return total, nil
}

// ValidateTimestamp shape-checks an RFC 3339 timestamp with a mandatory
// offset. Seconds may be omitted (the spec writes "2026-08-31T22:00Z").
// Calendar validity beyond cheap range checks is apply-time work.
func ValidateTimestamp(s string) error {
	b := []byte(s)
	fail := func() error {
		return fmt.Errorf("invalid timestamp `%s` — RFC 3339 with a mandatory offset, e.g. \"2026-08-31T22:00Z\" or \"...+02:00\"", s)
	}
	digit := func(i int) bool { return i < len(b) && b[i] >= '0' && b[i] <= '9' }
	at := func(i int, c byte) bool { return i < len(b) && b[i] == c }
	val := func(a, n int) int {
		v := 0
		for _, c := range b[a : a+n] {
			v = v*10 + int(c-'0')
		}
		return v
	}
	for i := range 4 {
		if !digit(i) {
			return fail()
		}
	}
	if !at(4, '-') || !digit(5) || !digit(6) || !at(7, '-') || !digit(8) || !digit(9) {
		return fail()
	}
	if !(at(10, 'T') || at(10, 't') || at(10, ' ')) {
		return fail()
	}
	if !digit(11) || !digit(12) || !at(13, ':') || !digit(14) || !digit(15) {
		return fail()
	}
	if m := val(5, 2); m < 1 || m > 12 {
		return fail()
	}
	if d := val(8, 2); d < 1 || d > 31 {
		return fail()
	}
	if val(11, 2) > 23 || val(14, 2) > 59 {
		return fail()
	}
	i := 16
	if at(i, ':') {
		if !digit(i+1) || !digit(i+2) || val(i+1, 2) > 60 {
			return fail()
		}
		i += 3
		if at(i, '.') {
			i++
			start := i
			for digit(i) {
				i++
			}
			if i == start {
				return fail()
			}
		}
	}
	switch {
	case at(i, 'Z') || at(i, 'z'):
		i++
	case at(i, '+') || at(i, '-'):
		if !digit(i+1) || !digit(i+2) || !at(i+3, ':') || !digit(i+4) || !digit(i+5) {
			return fail()
		}
		if val(i+1, 2) > 23 || val(i+4, 2) > 59 {
			return fail()
		}
		i += 6
	default:
		return fail()
	}
	if i != len(b) {
		return fail()
	}
	return nil
}
