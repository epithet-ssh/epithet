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
// list (predicates, require, when, notify). Conjunction is commutative and idempotent.

// ContentID returns the rule's full content id: 64 lowercase hex chars.
func (r *AllowRule) ContentID() string {
	proj := map[string]any{
		"effect":   "allow",
		"users":    canonicalSelector(r.Users, false),
		"accounts": canonicalSelector(r.Accounts, false),
		"hosts":    canonicalSelector(r.Hosts, false),
	}
	putList(proj, "require", r.Require)
	putList(proj, "when", r.When)
	putList(proj, "notify", r.Notify)
	if r.Until != nil {
		// RFC3339Nano, not RFC3339: the parser admits fractional
		// seconds, and dropping them here would give rules ending at
		// .1Z and .9Z the same content id — collapsing them to one.
		proj["until"] = r.Until.UTC().Format(time.RFC3339Nano)
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
		"users":    canonicalNegSelector(r.Users),
		"accounts": canonicalNegSelector(r.Accounts),
		"hosts":    canonicalNegSelector(r.Hosts),
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

// Predicate order and identical repetitions do not affect rule identity.
func canonicalSelector(s Selector, not bool) json.RawMessage {
	encs := make([]string, 0, len(s.Predicates))
	for _, p := range s.Predicates {
		encs = append(encs, string(mustMarshal(map[string]string{"attribute": p.Attribute, "value": p.Value})))
	}
	slices.Sort(encs)
	encs = slices.Compact(encs)
	raws := make([]json.RawMessage, len(encs))
	for i, e := range encs {
		raws[i] = json.RawMessage(e)
	}
	obj := map[string]any{"kind": s.Kind, "and": raws}
	if not {
		obj["not"] = true
	}
	return mustMarshal(obj)
}
func canonicalNegSelector(s NegatableSelector) json.RawMessage {
	return canonicalSelector(s.Selector, s.Not)
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
