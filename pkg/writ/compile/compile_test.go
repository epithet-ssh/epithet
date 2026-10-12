package compile

import (
	"strings"
	"testing"

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
	assertErr(t, "host prod = {env:prod}\nallow $prod -> a@b\n", "host macro, used in user position")
}

func TestDuplicateClauseIsError(t *testing.T) {
	assertErr(t, "allow group:A -> a@b, ttl 2m, ttl 3m\n", "duplicate `ttl`")
}

func TestUnusedMacroWarns(t *testing.T) {
	assertWarn(t, "user x = group:A\nallow group:B -> a@b\n", "never referenced")
}

func TestInvalidHostPatternSyntaxIsCompileError(t *testing.T) {
	tests := []string{
		`"host*.{internal,example.com}"`,
		`"host-[0-9]*.internal"`,
		`"host*/internal"`,
		"host**.internal",
		"host.***.internal",
	}
	for _, pattern := range tests {
		t.Run(pattern, func(t *testing.T) {
			assertErr(t, "allow group:A -> root@"+pattern+"\n", "invalid host pattern")
		})
	}
}

func TestMacroRenameKeepsContentID(t *testing.T) {
	a := compileOK(t, "user sre = group:SRE\nallow $sre -> root@h\n")
	b := compileOK(t, "user oncall = group:SRE\nallow $oncall -> root@h\n")
	require.Equal(t, a.Allows[0].ContentID(), b.Allows[0].ContentID())
}

// A timestamp the shape validator admits but the calendar rejects (a
// :60 leap second) errors during lowering; the policy must be nil, not
// a broader-than-authored rule with the until clause dropped.
func TestLoweringErrorReturnsNilPolicy(t *testing.T) {
	pol, errs, _ := analyze(t, "allow group:A -> a@b, until \"2026-08-31T22:00:60Z\"\n")
	require.NotEmpty(t, errs)
	require.Contains(t, errs[0], "invalid timestamp")
	require.Nil(t, pol)
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

func TestObjectLoweringAndAliases(t *testing.T) {
	p := compileOK(t, "user a = group{name:admins, role:oncall, role:operator}\nuser b = $a\nallow $b -> root@WEB{env:prod}\ndeny !$b -> !root@!{}\n")
	require.Equal(t, il.Group, p.Allows[0].Users.Kind)
	require.Len(t, p.Allows[0].Users.Predicates, 3)
	require.Equal(t, il.Predicate{Attribute: "name", Value: "web"}, p.Allows[0].Hosts.Predicates[0])
	require.True(t, p.Denies[0].Users.Not)
	require.True(t, p.Denies[0].Accounts.Not)
	require.True(t, p.Denies[0].Hosts.Not)
	require.NoError(t, p.Validate())
}
func TestEquivalentSpellingAndConjunctionOrder(t *testing.T) {
	for _, pair := range [][2]string{
		{`allow user:alice -> root@web`, `allow user{name:alice} -> root@{name:web}`},
		{`allow * -> *@*`, `allow user{} -> *@{}`},
		{`allow group{role:a, role:b, role:a} -> root@web{env:prod}`, `allow group{role:b, role:a} -> root@{env:prod,name:web}`},
	} {
		a := compileOK(t, pair[0])
		b := compileOK(t, pair[1])
		require.Equal(t, a.Allows[0].ContentID(), b.Allows[0].ContentID())
	}
	name := compileOK(t, `allow user:alice -> root@*`)
	id := compileOK(t, `allow user{id:alice} -> root@*`)
	require.NotEqual(t, name.Allows[0].ContentID(), id.Allows[0].ContentID())
}
func TestEmptyGroupIsNotEmptyUser(t *testing.T) {
	a := compileOK(t, `allow user{} -> root@*`)
	b := compileOK(t, `allow group{} -> root@*`)
	require.NotEqual(t, a.Allows[0].ContentID(), b.Allows[0].ContentID())
}
