package il

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Content identity per SPEC §11: id = sha256(canonical-projection),
// full digest stored, displayed as 12 lowercase hex characters.
//
// The canonical projection is computed for hashing only; the stored IL
// preserves authored order. It drops schema, id, and label; sorts
// object keys; omits empty and null fields; renders ttl as integer
// seconds and until as RFC 3339 UTC with Z; and sorts + dedups every
// list (match sets, require, when, notify) — lists are sets, and union
// and conjunction are both commutative and idempotent.

// ContentID returns the rule's full content id: 64 lowercase hex chars.
func (r *AllowRule) ContentID() string {
	proj := map[string]any{
		"effect":   "allow",
		"users":    canonicalMatchSet(r.Users, false),
		"accounts": canonicalMatchSet(r.Accounts, false),
		"hosts":    canonicalMatchSet(r.Hosts, false),
	}
	putList(proj, "require", r.Require)
	putList(proj, "when", r.When)
	putList(proj, "notify", r.Notify)
	if r.Until != nil {
		proj["until"] = r.Until.UTC().Format(time.RFC3339)
	}
	if r.TTL != 0 {
		proj["ttl"] = int64(r.TTL / time.Second)
	}
	return hashProjection(proj)
}

// ContentID returns the rule's full content id: 64 lowercase hex chars.
func (r *DenyRule) ContentID() string {
	proj := map[string]any{
		"effect":   "deny",
		"users":    canonicalNegSet(r.Users),
		"accounts": canonicalNegSet(r.Accounts),
		"hosts":    canonicalNegSet(r.Hosts),
	}
	putList(proj, "when", r.When)
	putList(proj, "notify", r.Notify)
	return hashProjection(proj)
}

// ShortID is the display form of a content id: its first 12 characters.
func ShortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

func putList(proj map[string]any, key string, vals []string) {
	if len(vals) == 0 {
		return
	}
	sorted := slices.Clone(vals)
	slices.Sort(sorted)
	proj[key] = slices.Compact(sorted)
}

// canonicalMatchSet renders a match set as {"or": [...]} (plus "not"
// when negated) with the matchers sorted bytewise by their own
// canonical encoding and deduplicated.
func canonicalMatchSet(s MatchSet, not bool) json.RawMessage {
	encs := make([]string, 0, len(s.Or))
	for _, m := range s.Or {
		encs = append(encs, string(canonicalMatcher(m)))
	}
	slices.Sort(encs)
	encs = slices.Compact(encs)

	raws := make([]json.RawMessage, len(encs))
	for i, e := range encs {
		raws[i] = json.RawMessage(e)
	}
	obj := map[string]any{"or": raws}
	if not {
		obj["not"] = true
	}
	return mustMarshal(obj)
}

func canonicalNegSet(s NegatableMatchSet) json.RawMessage {
	return canonicalMatchSet(s.MatchSet, s.Not)
}

// canonicalMatcher renders one matcher as its canonical JSON object.
// encoding/json sorts map keys, which is exactly the canonical-form
// requirement.
func canonicalMatcher(m Matcher) json.RawMessage {
	switch m.Kind {
	case MatchAny:
		return json.RawMessage(`{"any":true}`)
	case MatchLabels:
		return mustMarshal(map[string]any{"labels": m.Labels})
	default:
		return mustMarshal(map[string]any{string(m.Kind): m.Value})
	}
}

func hashProjection(proj map[string]any) string {
	sum := sha256.Sum256(mustMarshal(proj))
	return hex.EncodeToString(sum[:])
}

// mustMarshal is canonical-form JSON: sorted map keys (encoding/json's
// map behavior), compact, and without Go's default HTML escaping — a
// value containing `&` must hash identically from every future IL
// producer, never as the escaped & form.
func mustMarshal(v any) json.RawMessage {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Only reachable via an unmarshalable type, which would be a
		// programming error in this package.
		panic(fmt.Sprintf("il: canonical marshal: %v", err))
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}
