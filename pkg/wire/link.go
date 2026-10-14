package wire

import (
	"net/http"
	"strings"
)

// FindLinkTarget returns the target of the first link-value in h whose rel
// list contains rel. A single rel parameter may hold several space-separated
// relation types (RFC 8288 3.3), so membership is tested, not equality.
// Anchored links describe another context and are ignored.
func FindLinkTarget(h http.Header, rel string) (string, bool) {
	for _, field := range h.Values("Link") {
		for _, lv := range splitLinkFields(field, ',') {
			target, params, ok := parseLinkValue(lv)
			if !ok {
				continue
			}
			if _, anchored := params["anchor"]; anchored {
				continue
			}
			for _, candidate := range strings.Fields(params["rel"]) {
				if candidate == rel {
					return target, true
				}
			}
		}
	}
	return "", false
}

// splitLinkFields ignores separators inside targets and quoted strings.
func splitLinkFields(s string, separator byte) []string {
	var out []string
	var buf strings.Builder
	var inAngle, inQuote, escaped bool

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			buf.WriteByte(ch)
			escaped = false
			continue
		}
		switch {
		case inQuote && ch == '\\':
			escaped = true
		case ch == '"':
			inQuote = !inQuote
		case ch == '<' && !inQuote:
			inAngle = true
		case ch == '>' && !inQuote:
			inAngle = false
		case ch == separator && !inQuote && !inAngle:
			out = append(out, buf.String())
			buf.Reset()
			continue
		}
		buf.WriteByte(ch)
	}
	if strings.TrimSpace(buf.String()) != "" {
		out = append(out, buf.String())
	}
	return out
}

// parseLinkValue splits one link-value into its target and parameters.
// Parameter values are accepted in both token and quoted-string form, which
// RFC 8288 3 requires recipients to treat as equivalent. Only the first
// occurrence of a parameter is kept, per RFC 8288 3.3.
func parseLinkValue(lv string) (string, map[string]string, bool) {
	lv = strings.TrimSpace(lv)
	if !strings.HasPrefix(lv, "<") {
		return "", nil, false
	}
	end := strings.Index(lv, ">")
	if end < 0 {
		return "", nil, false
	}

	target := lv[1:end]
	params := map[string]string{}

	for _, p := range splitLinkFields(lv[end+1:], ';') {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key, value, found := strings.Cut(p, "=")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		}
		if _, dup := params[key]; !dup {
			params[key] = value
		}
	}
	return target, params, true
}
