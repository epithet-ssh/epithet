package il

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The SPEC §10 example rules, used as golden fixtures.

func specAllow() AllowRule {
	return AllowRule{
		Label:    "sre-prod-root",
		Users:    Selector{Kind: Group, Predicates: []Predicate{{Attribute: "name", Value: "SRE"}}},
		Accounts: Selector{Kind: Account, Predicates: []Predicate{{Attribute: "name", Value: "root"}}},
		Hosts:    Selector{Kind: Host, Predicates: []Predicate{{Attribute: "env", Value: "prod"}}},
		Require:  []string{"oncall", "approval"},
	}
}

func specDeny() DenyRule {
	return DenyRule{
		Label:    "prod-freeze",
		Users:    NegatableSelector{Not: true, Selector: Selector{Kind: Group, Predicates: []Predicate{{Attribute: "name", Value: "Infrastructure"}}}},
		Accounts: NegatableSelector{Selector: Selector{Kind: Account}},
		Hosts:    NegatableSelector{Selector: Selector{Kind: Host, Predicates: []Predicate{{Attribute: "env", Value: "prod"}}}},
		When:     []string{"freeze"},
	}
}

// Golden ids pin the hash encoding: any change to the canonical
// projection is a breaking change to every deployed rule id and must be
// deliberate.
func TestGoldenContentIDs(t *testing.T) {
	allow := specAllow()
	deny := specDeny()
	require.Equal(t, "6bdb0459a31963b5926c3a0616a427448f96da7cad313fe96f0f39972ae73922", allow.ContentID())
	require.Equal(t, "8d36fcd60b83dcc44a281e7148b51d8f6cba3f952e79c863fdb44590dfb44db3", deny.ContentID())
}

func TestShortIDIsTwelveHex(t *testing.T) {
	allow := specAllow()
	id := allow.ContentID()
	require.Len(t, id, 64)
	require.Len(t, ShortID(id), 12)
	require.Equal(t, id[:12], ShortID(id))
}

func TestListOrderDoesNotChangeID(t *testing.T) {
	a := specAllow()
	b := specAllow()
	b.Require = []string{"approval", "oncall"}
	require.Equal(t, a.ContentID(), b.ContentID())
}

func TestMatcherOrderDoesNotChangeID(t *testing.T) {
	a := specAllow()
	a.Users.Predicates = []Predicate{{Attribute: "name", Value: "SRE"}, {Attribute: "name", Value: "DBA"}}
	b := specAllow()
	b.Users.Predicates = []Predicate{{Attribute: "name", Value: "DBA"}, {Attribute: "name", Value: "SRE"}}
	require.Equal(t, a.ContentID(), b.ContentID())
}

func TestDuplicateEntriesCollapseInHash(t *testing.T) {
	a := specAllow()
	b := specAllow()
	b.Users.Predicates = []Predicate{{Attribute: "name", Value: "SRE"}, {Attribute: "name", Value: "SRE"}}
	b.Require = []string{"oncall", "approval", "oncall"}
	require.Equal(t, a.ContentID(), b.ContentID())
}

func TestLabelDoesNotChangeID(t *testing.T) {
	a := specAllow()
	b := specAllow()
	b.Label = "renamed"
	require.Equal(t, a.ContentID(), b.ContentID())
}

func TestSemanticEditsChangeID(t *testing.T) {
	base := specAllow()

	edited := specAllow()
	edited.Accounts.Predicates[0].Value = "postgres"
	require.NotEqual(t, base.ContentID(), edited.ContentID())

	withTTL := specAllow()
	withTTL.TTL = 2 * time.Minute
	require.NotEqual(t, base.ContentID(), withTTL.ContentID())

	until := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	withUntil := specAllow()
	withUntil.Until = &until
	require.NotEqual(t, base.ContentID(), withUntil.ContentID())

	withNotify := specAllow()
	withNotify.Notify = []string{"security-alerts"}
	require.NotEqual(t, base.ContentID(), withNotify.ContentID())
}

// Effect is hashed: an allow and a deny with identical positions are
// different rules.
func TestEffectIsHashed(t *testing.T) {
	allow := AllowRule{
		Users:    Selector{Kind: Group, Predicates: []Predicate{{Attribute: "name", Value: "SRE"}}},
		Accounts: Selector{Kind: Account},
		Hosts:    Selector{Kind: Host},
	}
	deny := DenyRule{
		Users:    NegatableSelector{Selector: Selector{Kind: Group, Predicates: []Predicate{{Attribute: "name", Value: "SRE"}}}},
		Accounts: NegatableSelector{Selector: Selector{Kind: Account}},
		Hosts:    NegatableSelector{Selector: Selector{Kind: Host}},
	}
	require.NotEqual(t, allow.ContentID(), deny.ContentID())
}

// The not bit is hashed: denying "not SRE" and denying "SRE" differ.
func TestNegationIsHashed(t *testing.T) {
	a := specDeny()
	b := specDeny()
	b.Users.Not = false
	require.NotEqual(t, a.ContentID(), b.ContentID())
}

// Fractional seconds are part of the instant: untils at .1Z and .9Z
// are different rules and must not collapse to one content id.
func TestUntilFractionalSecondsAreHashed(t *testing.T) {
	early := time.Date(2026, 8, 31, 22, 0, 0, 100_000_000, time.UTC)
	late := time.Date(2026, 8, 31, 22, 0, 0, 900_000_000, time.UTC)
	a := specAllow()
	a.Until = &early
	b := specAllow()
	b.Until = &late
	require.NotEqual(t, a.ContentID(), b.ContentID())
}

// An until in a non-UTC zone hashes identically to its UTC instant.
func TestUntilNormalizesToUTC(t *testing.T) {
	utc := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)
	offset := utc.In(time.FixedZone("CEST", 2*3600))
	a := specAllow()
	a.Until = &utc
	b := specAllow()
	b.Until = &offset
	require.Equal(t, a.ContentID(), b.ContentID())
}

func TestHostName(t *testing.T) {
	require.Equal(t, "web-1.example.com", HostName("Web-1.EXAMPLE.com"))
	require.Equal(t, "already-lower", HostName("already-lower"))
	// ASCII-only folding: multibyte characters pass through untouched.
	require.Equal(t, "über-host", HostName("über-host"))
}
