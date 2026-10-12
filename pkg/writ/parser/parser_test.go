package parser

import (
	"github.com/epithet-ssh/epithet/pkg/writ/ast"
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
)

func TestObjectSelectors(t *testing.T) {
	for _, src := range []string{
		`allow user:alice -> root@web`,
		`allow user{name:alice, department:engineering} -> root@web{region:eu-west-1}`,
		`allow group{id:abc, role:admin, role:oncall} -> root@{}`,
		`allow group{} -> *@*`,
		"user a = group:admins\nuser b = $a\nallow $b -> root@*",
		`deny !group{name:admins} -> !root@!{environment:production}, when freeze`,
		`allow user{"flat/key":"a:b", name:"alice@example.com"} -> "ub*"@**.example.com`,
		`allow user{name:""} -> root@host{environment:production}`,
		"allow user{\n name:alice, # comment\n department:engineering\n} -> root@*",
		`allow user:alice -> root@*, require [oncall, approval], ttl 2m, notify "alerts", label "access"`,
	} {
		t.Run(src, func(t *testing.T) { _, ds := Parse(src); require.Empty(t, diag.Errors(ds)) })
	}
}
func TestForbiddenForms(t *testing.T) {
	for _, src := range []string{
		`allow [user:alice, user:bob] -> root@*`, `allow user:alice -> [root,ubuntu]@*`,
		`allow user:alice -> root@[a,b]`, `user a = [group:a,group:b]`,
		`allow !user:alice -> root@*`, `user a = !group:a`, `deny !!group:a -> root@*`,
		`allow user{!name:alice} -> root@*`, `allow user{name:!alice} -> root@*`,
		`allow userName:alice -> root@*`, `allow id:a -> root@*`,
		`allow device{name:a} -> root@*`, `allow {name:alice} -> root@*`,
		`allow user:alice -> root@*{env:prod}`, `allow user:alice -> {name:root}@*`,
		`allow user:alice -> root@{env=prod}`, `allow user{env:[prod,dev]} -> root@*`,
		`allow user{env:{nested:value}} -> root@*`, `allow user:name* -> root@*`,
		`allow user {name:alice -> root@*`, `allow user{name:"bad\n"} -> root@*`,
		`deny * -> *@*, require approval`, `deny * -> *@*, ttl 2m`, `deny * -> *@*, until "2026-01-01T00:00Z"`,
	} {
		t.Run(src, func(t *testing.T) { _, ds := Parse(src); require.NotEmpty(t, diag.Errors(ds)) })
	}
}
func TestHostPrefixIsNamePredicate(t *testing.T) {
	f, ds := Parse(`allow group:admins -> root@host{role:db}`)
	require.Empty(t, diag.Errors(ds))
	r := f.Items[0].(*ast.AllowRule)
	h := r.Hosts.Atom.(*ast.Filter)
	require.Equal(t, "host", h.Object)
	require.Len(t, h.Pairs, 2)
	require.Equal(t, "name", h.Pairs[0].Key.Text)
	require.Equal(t, "host", h.Pairs[0].Value.Text)
}
func TestRecoveryAndStringEscapes(t *testing.T) {
	f, ds := Parse("allow !user:a -> root@*\nallow user{name:\"a\\\"b\\\\c\"} -> root@*\n")
	require.NotEmpty(t, diag.Errors(ds))
	require.Len(t, f.Items, 1)
	u := f.Items[0].(*ast.AllowRule).Users.Atom.(*ast.Filter)
	require.Equal(t, "a\"b\\c", u.Pairs[0].Value.Text)
}

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
	require.Equal(t, 13, rules)
}

func TestAdjacentRulesAreSeparateStatements(t *testing.T) {
	file := parseOK(t, "allow group:A -> a@b\nallow group:B -> c@d\n")
	require.Len(t, file.Items, 2)
}

func TestTrailingCommaContinuesToNextLine(t *testing.T) {
	src := "allow user:\"carol@example.com\" -> postgres@prod-db-1,\n    require approval,\n    until \"2026-08-31T22:00Z\",\n    label \"carol\"\n"
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

func TestArrowMunchesWithoutWhitespace(t *testing.T) {
	file := parseOK(t, "user sre = group:SRE\nallow $sre->root@db-1\n")
	rule := file.Items[1].(*ast.AllowRule)
	name := rule.Accounts.Atom.(*ast.Name)
	require.Equal(t, "root", name.Value.Text)
	host := rule.Hosts.Atom.(*ast.Filter)
	require.Equal(t, "db-1", host.Pairs[0].Value.Text)
}

func TestEmptyAndCommentOnlyFiles(t *testing.T) {
	require.Empty(t, parseOK(t, "").Items)
	require.Empty(t, parseOK(t, "# just a comment\n\n# another\n").Items)
}

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
