package hostpattern

// NormalizeName applies ASCII case folding at host ingress boundaries.
func NormalizeName(s string) string {
	lowered := []byte(s)
	changed := false
	for i, c := range lowered {
		if c >= 'A' && c <= 'Z' {
			lowered[i] = c + ('a' - 'A')
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(lowered)
}
