package eval

// GlobMatch matches writ globs: `*` and `?` only — no character
// classes, no `**`. `*` matches any run of bytes including dots (host
// names are writ registrations, not DNS labels, so there is no
// hierarchy for a glob to respect). Comparison is byte-exact, so `?`
// matches one byte. Exported for inventory implementations that match
// host names against configured patterns with the language's glob
// semantics.
func GlobMatch(pattern, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
