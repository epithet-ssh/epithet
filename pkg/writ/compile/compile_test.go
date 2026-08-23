package compile

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/writ/diag"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
	"github.com/epithet-ssh/epithet/pkg/writ/parser"
	"github.com/stretchr/testify/require"
)

// analyze mirrors the reference implementation's analyze(): parse then
// check/compile, with errors and warnings split.
func analyze(t *testing.T, src string) (*il.Policy, []string, []string) {
	t.Helper()
	file, diags := parser.Parse(src)
	pol, cdiags := Compile(file)
	diags = append(diags, cdiags...)
	var errs, warns []string
	for _, d := range diags {
		if d.Severity == diag.Error {
			errs = append(errs, d.Msg)
		} else {
			warns = append(warns, d.Msg)
		}
	}
	return pol, errs, warns
}

func compileOK(t *testing.T, src string) *il.Policy {
	t.Helper()
	pol, errs, _ := analyze(t, src)
	require.Empty(t, errs, "unexpected errors")
	require.NotNil(t, pol)
	return pol
}

func assertErr(t *testing.T, src, needle string) {
	t.Helper()
	_, errs, _ := analyze(t, src)
	for _, m := range errs {
		if strings.Contains(m, needle) {
			return
		}
	}
	t.Fatalf("no error containing %q in %#v", needle, errs)
}

func assertWarn(t *testing.T, src, needle string) {
	t.Helper()
	_, errs, warns := analyze(t, src)
	require.Empty(t, errs, "unexpected errors")
	for _, m := range warns {
		if strings.Contains(m, needle) {
			return
		}
	}
	t.Fatalf("no warning containing %q in %#v", needle, warns)
}

// ── well-formedness (ported from parse.rs) ──────────────────────────

func TestUndefinedMacroIsError(t *testing.T) {
	assertErr(t, "allow $sre -> a@b\n", "referenced before definition")
}

func TestUseBeforeDefinitionIsError(t *testing.T) {
	assertErr(t, "allow $sre -> a@b\nuser sre = group:SRE\n", "referenced before definition")
}

func TestMacroRedefinitionIsError(t *testing.T) {
	assertErr(t, "user x = group:A\nuser x = group:B\n", "redefined")
}

func TestMacroKindMismatchIsError(t *testing.T) {
	assertErr(t, "host prod = {env=prod}\nallow $prod -> a@b\n", "host macro, used in user position")
}

func TestDuplicateClauseIsError(t *testing.T) {
	assertErr(t, "allow group:A -> a@b, ttl 2m, ttl 3m\n", "duplicate `ttl`")
}

func TestDuplicateSelectorKeyIsError(t *testing.T) {
	assertErr(t, "allow group:A -> a@{env=prod, env=dev}\n", "duplicate key")
}

func TestUnusedMacroWarns(t *testing.T) {
	assertWarn(t, "user x = group:A\nallow group:B -> a@b\n", "never referenced")
}

func TestDuplicateListEntryWarns(t *testing.T) {
	assertWarn(t, "allow group:A -> [a, a]@b\n", "duplicate list entry")
}

// ── the scenario corpus ─────────────────────────────────────────────

func TestScenarioFileCompilesClean(t *testing.T) {
	src, err := os.ReadFile("../testdata/scenarios.writ")
	require.NoError(t, err)
	pol, errs, warns := analyze(t, string(src))
	require.Empty(t, errs)
	require.Empty(t, warns)
	require.Len(t, pol.Allows, 8)
	require.Len(t, pol.Denies, 2)

	// S2: allow $sre -> root@$prod, require [oncall, approval], label "sre-prod-root".
	s2 := pol.Allows[1]
	require.Equal(t, "sre-prod-root", s2.Label)
	require.Equal(t, []il.Matcher{{Kind: il.MatchGroup, Value: "SRE"}}, s2.Users.Or)
	require.Equal(t, []il.Matcher{{Kind: il.MatchName, Value: "root"}}, s2.Accounts.Or)
	require.Equal(t, []il.Matcher{{Kind: il.MatchLabels, Labels: map[string]string{"env": "prod"}}}, s2.Hosts.Or)
	require.Equal(t, []string{"oncall", "approval"}, s2.Require)

	// S8: deny !$infra -> *@$prod, when freeze, label "prod-freeze".
	s8 := pol.Denies[1]
	require.Equal(t, "prod-freeze", s8.Label)
	require.True(t, s8.Users.Not)
	require.Equal(t, []il.Matcher{{Kind: il.MatchGroup, Value: "Infrastructure"}}, s8.Users.Or)
	require.Equal(t, []il.Matcher{{Kind: il.MatchAny}}, s8.Accounts.Or)
	require.Equal(t, []string{"freeze"}, s8.When)

	// The stress rule: ttl 2m lowers to a 120s duration.
	stress := pol.Allows[6]
	require.Equal(t, "db-root-breakglass", stress.Label)
	require.Equal(t, 2*time.Minute, stress.TTL)
	require.Equal(t, []string{"security-alerts"}, stress.Notify)

	// S3: until "2026-08-31T22:00Z" parses to the absolute instant.
	s3 := pol.Allows[2]
	require.NotNil(t, s3.Until)
	require.Equal(t, time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC), s3.Until.UTC())
}

// ── lowering ────────────────────────────────────────────────────────

func TestSplicesFlatten(t *testing.T) {
	pol := compileOK(t, "user sre = [group:SRE, group:Infra]\nallow [$sre, group:X] -> a@b\n")
	require.Equal(t, []il.Matcher{
		{Kind: il.MatchGroup, Value: "SRE"},
		{Kind: il.MatchGroup, Value: "Infra"},
		{Kind: il.MatchGroup, Value: "X"},
	}, pol.Allows[0].Users.Or)
}

func TestMacroOfMacroFlattens(t *testing.T) {
	pol := compileOK(t, "user a = group:A\nuser b = [$a, group:B]\nallow $b -> x@y\n")
	require.Equal(t, []il.Matcher{
		{Kind: il.MatchGroup, Value: "A"},
		{Kind: il.MatchGroup, Value: "B"},
	}, pol.Allows[0].Users.Or)
}

func TestGlobVersusNameVersusAny(t *testing.T) {
	pol := compileOK(t, "allow group:A -> [ub*, root, *]@db-?\n")
	require.Equal(t, []il.Matcher{
		{Kind: il.MatchGlob, Value: "ub*"},
		{Kind: il.MatchName, Value: "root"},
		{Kind: il.MatchAny},
	}, pol.Allows[0].Accounts.Or)
	require.Equal(t, []il.Matcher{{Kind: il.MatchGlob, Value: "db-?"}}, pol.Allows[0].Hosts.Or)
}

// A surface `*` compiles to any, never to a glob.
func TestStarCompilesToAnyNotGlob(t *testing.T) {
	pol := compileOK(t, "allow * -> *@*\n")
	for _, set := range []il.MatchSet{pol.Allows[0].Users, pol.Allows[0].Accounts, pol.Allows[0].Hosts} {
		require.Equal(t, []il.Matcher{{Kind: il.MatchAny}}, set.Or)
	}
}

// Host names and globs are lowercased at compilation; account names,
// tag values, and labels are untouched.
func TestHostNamesLowercaseAtCompile(t *testing.T) {
	pol := compileOK(t, "allow group:SRE -> Root@[WEB-1, WEB-*]\n")
	require.Equal(t, []il.Matcher{{Kind: il.MatchName, Value: "Root"}}, pol.Allows[0].Accounts.Or)
	require.Equal(t, []il.Matcher{
		{Kind: il.MatchName, Value: "web-1"},
		{Kind: il.MatchGlob, Value: "web-*"},
	}, pol.Allows[0].Hosts.Or)
	require.Equal(t, "SRE", pol.Allows[0].Users.Or[0].Value)
}

// Quoting is a rendering decision: a quoted glob in name position
// globs exactly like a bare one.
func TestQuotedGlobInNamePositionGlobs(t *testing.T) {
	pol := compileOK(t, "allow group:A -> \"ub*\"@h\n")
	require.Equal(t, il.MatchGlob, pol.Allows[0].Accounts.Or[0].Kind)
}

func TestMacroRenameKeepsContentID(t *testing.T) {
	a := compileOK(t, "user sre = group:SRE\nallow $sre -> root@h\n")
	b := compileOK(t, "user oncall = group:SRE\nallow $oncall -> root@h\n")
	require.Equal(t, a.Allows[0].ContentID(), b.Allows[0].ContentID())
}

func TestDuplicateContentIDWarnsAndCollapses(t *testing.T) {
	pol, errs, warns := analyze(t, "allow group:A -> a@b\nallow group:A -> a@b, label \"x\"\n")
	require.Empty(t, errs)
	require.Len(t, warns, 1)
	require.Contains(t, warns[0], "collapse")
	require.Len(t, pol.Allows, 1)
	// The first label (here: none) wins.
	require.Equal(t, "", pol.Allows[0].Label)
}
