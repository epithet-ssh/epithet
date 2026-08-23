package parser

import (
	"os"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/writ/ast"
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
	"github.com/stretchr/testify/require"
)

// Ported from the reference implementation's parse.rs. The check-level
// cases (macro resolution, duplicate clauses/keys, warnings) live in
// the compile package; everything here is parse-time behavior.

func parseErrors(t *testing.T, src string) []string {
	t.Helper()
	_, diags := Parse(src)
	var msgs []string
	for _, d := range diag.Errors(diags) {
		msgs = append(msgs, d.Msg)
	}
	return msgs
}

func parseOK(t *testing.T, src string) *ast.File {
	t.Helper()
	file, diags := Parse(src)
	require.Empty(t, diag.Errors(diags), "unexpected errors")
	return file
}

func assertErr(t *testing.T, src, needle string) {
	t.Helper()
	msgs := parseErrors(t, src)
	for _, m := range msgs {
		if strings.Contains(m, needle) {
			return
		}
	}
	t.Fatalf("no error containing %q in %#v", needle, msgs)
}

// ── the scenario corpus ─────────────────────────────────────────────

func TestScenarioFileParsesClean(t *testing.T) {
	src, err := os.ReadFile("../testdata/scenarios.writ")
	require.NoError(t, err)
	file := parseOK(t, string(src))
	macros, rules := 0, 0
	for _, item := range file.Items {
		if _, ok := item.(*ast.MacroDef); ok {
			macros++
		} else {
			rules++
		}
	}
	require.Equal(t, 8, macros)
	require.Equal(t, 10, rules)
}

func TestSimpleRuleShape(t *testing.T) {
	file := parseOK(t, "user sre = group:SRE\nallow $sre -> ubuntu@{env=prod}\n")
	require.Len(t, file.Items, 2)
	rule, ok := file.Items[1].(*ast.AllowRule)
	require.True(t, ok, "expected allow rule")

	require.Len(t, rule.Users.Atoms, 1)
	ref, ok := rule.Users.Atoms[0].(*ast.MacroRef)
	require.True(t, ok)
	require.Equal(t, "sre", ref.Name)

	name, ok := rule.Accounts.Atoms[0].(*ast.Name)
	require.True(t, ok)
	require.Equal(t, "ubuntu", name.Value.Text)
	require.False(t, name.Value.Quoted)

	sel, ok := rule.Hosts.Atoms[0].(*ast.Labels)
	require.True(t, ok, "expected selector")
	require.Len(t, sel.Pairs, 1)
	require.Equal(t, "env", sel.Pairs[0].Key.Text)
	require.Equal(t, "prod", sel.Pairs[0].Value.Text)
}

func TestDenyNegationAndTags(t *testing.T) {
	file := parseOK(t, "user infra = group:Infrastructure\ndeny !$infra -> *@{env=prod}, when freeze\n")
	rule, ok := file.Items[1].(*ast.DenyRule)
	require.True(t, ok, "expected deny rule")
	require.True(t, rule.Users.Not)
	require.False(t, rule.Accounts.Not)
	_, isAny := rule.Accounts.Atoms[0].(*ast.Any)
	require.True(t, isAny)
	require.Len(t, rule.Clauses, 1)
	when, ok := rule.Clauses[0].(*ast.When)
	require.True(t, ok)
	require.Equal(t, "freeze", when.Names[0].Text)
}

func TestStarIsLegalInUserPosition(t *testing.T) {
	file := parseOK(t, "allow * -> ubuntu@{env=dev}\n")
	rule := file.Items[0].(*ast.AllowRule)
	_, isAny := rule.Users.Atoms[0].(*ast.Any)
	require.True(t, isAny)
}

func TestTagMatcherShape(t *testing.T) {
	file := parseOK(t, "allow id:\"carol@example.com\" -> postgres@db-1\n")
	rule := file.Items[0].(*ast.AllowRule)
	tag, ok := rule.Users.Atoms[0].(*ast.TagMatcher)
	require.True(t, ok, "expected tag")
	require.Equal(t, ast.TagID, tag.Tag)
	require.Equal(t, "carol@example.com", tag.Value.Text)
	require.True(t, tag.Value.Quoted)
}

// ── statement termination and continuation ──────────────────────────

func TestAdjacentRulesAreSeparateStatements(t *testing.T) {
	file := parseOK(t, "allow group:A -> a@b\nallow group:B -> c@d\n")
	require.Len(t, file.Items, 2)
}

func TestTrailingCommaContinuesToNextLine(t *testing.T) {
	src := "allow id:\"carol@example.com\" -> postgres@prod-db-1,\n    require approval,\n    until \"2026-08-31T22:00Z\",\n    label \"carol\"\n"
	file := parseOK(t, src)
	require.Len(t, file.Items, 1)
	rule := file.Items[0].(*ast.AllowRule)
	require.Len(t, rule.Clauses, 3)
}

func TestCommentAfterTrailingCommaStillContinues(t *testing.T) {
	file := parseOK(t, "allow group:A -> root@h,  # gate below\n    require mfa\n")
	require.Len(t, file.Items, 1)
	rule := file.Items[0].(*ast.AllowRule)
	require.Len(t, rule.Clauses, 1)
}

func TestTrailingCommaAtEOFIsError(t *testing.T) {
	require.NotEmpty(t, parseErrors(t, "allow group:A -> a@b,"))
}

func TestTrailingCommaInsideListIsLegal(t *testing.T) {
	parseOK(t, "allow group:A -> [a, b,]@c\n")
}

func TestNewlinesInsideBracketsAreWhitespace(t *testing.T) {
	parseOK(t, "allow group:A -> [\n  a,\n  b\n]@{\n  env=prod,\n}\n")
}

func TestArrowMunchesWithoutWhitespace(t *testing.T) {
	file := parseOK(t, "user sre = group:SRE\nallow $sre->root@db-1\n")
	rule := file.Items[1].(*ast.AllowRule)
	name := rule.Accounts.Atoms[0].(*ast.Name)
	require.Equal(t, "root", name.Value.Text)
	host := rule.Hosts.Atoms[0].(*ast.Name)
	require.Equal(t, "db-1", host.Value.Text)
}

func TestEmptyAndCommentOnlyFiles(t *testing.T) {
	require.Empty(t, parseOK(t, "").Items)
	require.Empty(t, parseOK(t, "# just a comment\n\n# another\n").Items)
}

// ── negation restrictions ───────────────────────────────────────────

func TestNegatedAllowIsRejected(t *testing.T) {
	assertErr(t, "!group:A -> root@h\n", "deny")
}

func TestNegationMidAllowHeadIsRejected(t *testing.T) {
	assertErr(t, "allow group:A -> !root@h\n", "only legal on deny")
}

func TestNegationInsideListIsDeMorganError(t *testing.T) {
	assertErr(t, "deny [!group:A, group:B] -> *@*\n", "whole expression")
}

func TestNegationInMacroBodyIsRejected(t *testing.T) {
	assertErr(t, "user notinfra = !group:Infrastructure\n", "macro bodies")
}

// ── deny-only clause restrictions ───────────────────────────────────

func TestRequireOnDenyIsRejected(t *testing.T) {
	assertErr(t, "deny group:A -> *@*, require mfa\n", "not legal on a deny")
}

func TestUntilOnDenyIsRejected(t *testing.T) {
	assertErr(t, "deny group:A -> *@*, until \"2026-08-31T22:00Z\"\n", "allow-only")
}

func TestTTLOnDenyIsRejected(t *testing.T) {
	assertErr(t, "deny group:A -> *@*, ttl 5m\n", "allow-only")
}

// ── globs match names, never attribute values ───────────────────────

func TestGlobInTagValueIsRejected(t *testing.T) {
	assertErr(t, "allow group:SRE* -> root@h1\n", "never attribute values")
}

func TestGlobInLabelValueIsRejected(t *testing.T) {
	assertErr(t, "allow group:A -> root@{env=prod*}\n", "never attribute values")
}

func TestGlobInLabelKeyIsRejected(t *testing.T) {
	assertErr(t, "allow group:A -> root@{env*=prod}\n", "label keys")
}

func TestQuotedGlobIsALiteral(t *testing.T) {
	parseOK(t, "allow group:\"weird*name\" -> root@h1\n")
}

func TestNameGlobsStayLegal(t *testing.T) {
	parseOK(t, "allow group:A -> ub*@db-?\n")
}

// ── keyword and shape errors ────────────────────────────────────────

func TestKeywordMacroNameIsError(t *testing.T) {
	assertErr(t, "user deny = group:A\n", "keyword")
	assertErr(t, "user allow = group:A\n", "keyword")
}

func TestUppercaseKeywordsDoNotLex(t *testing.T) {
	require.NotEmpty(t, parseErrors(t, "DENY group:A -> *@*\n"))
}

func TestBareWordCannotStartARule(t *testing.T) {
	require.NotEmpty(t, parseErrors(t, "carol -> a@b\n"))
}

func TestHeadlessRuleGetsMigrationError(t *testing.T) {
	assertErr(t, "group:A -> a@b\n", "missing `allow`")
	assertErr(t, "$sre -> a@b, ttl 2m\n", "missing `allow`")
	assertErr(t, "* -> ubuntu@dev-1\n", "missing `allow`")
	assertErr(t, "[group:A, group:B] -> a@b\n", "missing `allow`")
}

func TestLabelRequiresQuotes(t *testing.T) {
	assertErr(t, "allow group:A -> a@b, label foo\n", "quoted string")
}

func TestUnterminatedStringIsError(t *testing.T) {
	require.NotEmpty(t, parseErrors(t, "group:\"A -> a@b\n"))
}

func TestLabelSelectorOutsideHostPositionIsError(t *testing.T) {
	require.NotEmpty(t, parseErrors(t, "{env=prod} -> a@b\n"))
	assertErr(t, "allow group:A -> {env=prod}@h\n", "host position")
}

// ── token validators ────────────────────────────────────────────────

func TestDurations(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint64
	}{
		{"2m", 120}, {"90s", 90}, {"1h30m", 5400},
	} {
		got, err := ParseDuration(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.want, got, tc.in)
	}
	for _, in := range []string{"2", "m", "2d", ""} {
		_, err := ParseDuration(in)
		require.Error(t, err, in)
	}

	// Zero would collide with the IL's "no ttl set" sentinel.
	for _, in := range []string{"0s", "0m", "0h0m0s"} {
		_, err := ParseDuration(in)
		require.ErrorContains(t, err, "positive", in)
	}

	// Values past time.Duration's range are rejected, not wrapped —
	// including per-part multiplication overflow, summed-parts
	// overflow, and integers strconv itself cannot hold.
	for _, in := range []string{
		"9223372037s",                    // maxDurationSeconds + 1
		"9999999999999999999h",           // n * 3600 overflows
		"9223372036s9223372036s",         // parts sum past the cap
		"99999999999999999999999999999s", // exceeds uint64
	} {
		_, err := ParseDuration(in)
		require.ErrorContains(t, err, "too large", in)
	}

	// The largest representable duration still parses.
	got, err := ParseDuration("9223372036s")
	require.NoError(t, err)
	require.Equal(t, uint64(9223372036), got)
}

func TestTimestamps(t *testing.T) {
	for _, in := range []string{
		"2026-08-31T22:00Z",
		"2026-08-31T22:00:00+02:00",
		"2026-08-31T22:00:00.123Z",
	} {
		require.NoError(t, ValidateTimestamp(in), in)
	}
	for _, in := range []string{
		"2026-08-31T22:00", // offset mandatory
		"2026-13-01T00:00Z",
		"not-a-time",
	} {
		require.Error(t, ValidateTimestamp(in), in)
	}
}
