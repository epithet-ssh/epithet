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
		Users:    MatchSet{Or: []Matcher{{Kind: MatchGroup, Value: "SRE"}}},
		Accounts: MatchSet{Or: []Matcher{{Kind: MatchName, Value: "root"}}},
		Hosts:    MatchSet{Or: []Matcher{{Kind: MatchLabels, Labels: map[string]string{"env": "prod"}}}},
		Require:  []string{"oncall", "approval"},
	}
}

func specDeny() DenyRule {
	return DenyRule{
		Label:    "prod-freeze",
		Users:    NegatableMatchSet{Not: true, MatchSet: MatchSet{Or: []Matcher{{Kind: MatchGroup, Value: "Infrastructure"}}}},
		Accounts: NegatableMatchSet{MatchSet: MatchSet{Or: []Matcher{{Kind: MatchAny}}}},
		Hosts:    NegatableMatchSet{MatchSet: MatchSet{Or: []Matcher{{Kind: MatchLabels, Labels: map[string]string{"env": "prod"}}}}},
		When:     []string{"freeze"},
	}
}

// Golden ids pin the hash encoding: any change to the canonical
// projection is a breaking change to every deployed rule id and must be
// deliberate.
func TestGoldenContentIDs(t *testing.T) {
	allow := specAllow()
	deny := specDeny()
	require.Equal(t, "30832649653f8b9231bd5a3c31268bb89e08d8e59ac6c0b2d456968368070b3e", allow.ContentID())
	require.Equal(t, "0f569d6d1a4ac431e4a397eb7e10d43c0957ee4825ce8317fe1ae25f23f1ebd3", deny.ContentID())
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
	a.Users.Or = []Matcher{{Kind: MatchGroup, Value: "SRE"}, {Kind: MatchGroup, Value: "DBA"}}
	b := specAllow()
	b.Users.Or = []Matcher{{Kind: MatchGroup, Value: "DBA"}, {Kind: MatchGroup, Value: "SRE"}}
	require.Equal(t, a.ContentID(), b.ContentID())
}

func TestDuplicateEntriesCollapseInHash(t *testing.T) {
	a := specAllow()
	b := specAllow()
	b.Users.Or = []Matcher{{Kind: MatchGroup, Value: "SRE"}, {Kind: MatchGroup, Value: "SRE"}}
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
	edited.Accounts.Or[0].Value = "postgres"
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
		Users:    MatchSet{Or: []Matcher{{Kind: MatchGroup, Value: "SRE"}}},
		Accounts: MatchSet{Or: []Matcher{{Kind: MatchAny}}},
		Hosts:    MatchSet{Or: []Matcher{{Kind: MatchAny}}},
	}
	deny := DenyRule{
		Users:    NegatableMatchSet{MatchSet: MatchSet{Or: []Matcher{{Kind: MatchGroup, Value: "SRE"}}}},
		Accounts: NegatableMatchSet{MatchSet: MatchSet{Or: []Matcher{{Kind: MatchAny}}}},
		Hosts:    NegatableMatchSet{MatchSet: MatchSet{Or: []Matcher{{Kind: MatchAny}}}},
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
