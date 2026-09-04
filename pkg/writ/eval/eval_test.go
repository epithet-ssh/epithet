package eval_test

import (
	"errors"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/epithet-ssh/epithet/pkg/writ/eval"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
	"github.com/stretchr/testify/require"
)

// Decision tables for SPEC §8, driven through real policy source so
// compile and eval are exercised together.

func policy(t *testing.T, src string) *il.Policy {
	t.Helper()
	pol, diags := writ.Load(src)
	require.NotNil(t, pol, "policy failed to load: %v", diags)
	return pol
}

func sreUser() *eval.User {
	return &eval.User{ID: "alice@example.com", Active: true, Groups: []string{"SRE"}, Type: "employee"}
}

func prodHost() *eval.Host {
	return &eval.Host{Name: "prod-db-1", Labels: map[string]string{"env": "prod", "role": "db"}}
}

func noFlags(name string) (bool, error)           { return false, nil }
func noFacts(name string) (eval.FactState, error) { return eval.FactUnknown, nil }

func flagsFrom(m map[string]bool) eval.FlagFunc {
	return func(name string) (bool, error) { return m[name], nil }
}

func factsFrom(m map[string]eval.FactState) eval.FactFunc {
	return func(name string) (eval.FactState, error) { return m[name], nil }
}

func decide(t *testing.T, src string, req eval.Request) eval.Decision {
	t.Helper()
	d, err := eval.Decide(policy(t, src), req, time.Now(), noFlags, noFacts)
	require.NoError(t, err)
	return d
}

// ── structural gates ────────────────────────────────────────────────

func TestNilUserIsStructuralDeny(t *testing.T) {
	d := decide(t, "allow * -> *@*\n", eval.Request{Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
	require.Contains(t, d.Reason, "active inventory user")
}

func TestInactiveUserIsStructuralDeny(t *testing.T) {
	u := sreUser()
	u.Active = false
	d := decide(t, "allow * -> *@*\n", eval.Request{User: u, Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
}

func TestNilHostIsStructuralDeny(t *testing.T) {
	d := decide(t, "allow * -> *@*\n", eval.Request{User: sreUser(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
	require.Contains(t, d.Reason, "host")
}

func TestGroundedAccountMissIsStructuralDeny(t *testing.T) {
	h := prodHost()
	h.Accounts = []string{"ubuntu", "postgres"}
	d := decide(t, "allow * -> *@*\n", eval.Request{User: sreUser(), Host: h, Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
	require.Contains(t, d.Reason, "account")
}

func TestGroundedAccountHitIssues(t *testing.T) {
	h := prodHost()
	h.Accounts = []string{"ubuntu", "root"}
	d := decide(t, "allow * -> *@*\n", eval.Request{User: sreUser(), Host: h, Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)
}

func TestUngroundedHostMatchesRequestedAccount(t *testing.T) {
	d := decide(t, "allow * -> *@*\n", eval.Request{User: sreUser(), Host: prodHost(), Account: "anything"})
	require.Equal(t, eval.Issue, d.Outcome)
}

// An empty (non-nil) accounts list grounds nothing.
func TestEmptyAccountsListGroundsNothing(t *testing.T) {
	h := prodHost()
	h.Accounts = []string{}
	d := decide(t, "allow * -> *@*\n", eval.Request{User: sreUser(), Host: h, Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
}

// ── matching and deny-wins ──────────────────────────────────────────

func TestSimpleAllowIssues(t *testing.T) {
	src := "user sre = group:SRE\nhost prod = {env=prod}\nallow $sre -> root@$prod\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)
	require.Len(t, d.Allowed, 1)
}

func TestNoMatchDenies(t *testing.T) {
	src := "user dba = group:DBA\nallow $dba -> root@*\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
}

func TestDenyWinsOverAllow(t *testing.T) {
	src := "allow group:SRE -> root@*\ndeny type:employee -> root@{env=prod}, label \"no-emp-root\"\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
	require.NotNil(t, d.DenyRule)
	require.Equal(t, "no-emp-root", d.DenyRule.Label)
}

// File order never matters: the same deny wins when authored first.
func TestDenyWinsRegardlessOfFileOrder(t *testing.T) {
	src := "deny type:employee -> root@{env=prod}\nallow group:SRE -> root@*\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
	require.NotNil(t, d.DenyRule)
}

func TestNegatedDenyMatchesOutsiders(t *testing.T) {
	src := "user infra = group:Infrastructure\nallow * -> *@*\ndeny !$infra -> *@{env=prod}\n"
	// An SRE (not Infrastructure) is caught by the negated deny.
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
	require.NotNil(t, d.DenyRule)
	// An Infrastructure member is not.
	infra := &eval.User{ID: "bob", Active: true, Groups: []string{"Infrastructure"}}
	d = decide(t, src, eval.Request{User: infra, Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)
}

// `![$a, $b]` means "in neither".
func TestNegatedListMeansInNeither(t *testing.T) {
	src := "allow * -> *@*\ndeny ![group:SRE, group:DBA] -> *@*\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome, "SRE is in the union, deny must not fire")
	outsider := &eval.User{ID: "eve", Active: true, Groups: []string{"Sales"}}
	d = decide(t, src, eval.Request{User: outsider, Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
	require.NotNil(t, d.DenyRule)
}

// ── sync conditions: when and until ─────────────────────────────────

func TestDenyWhenFlagGates(t *testing.T) {
	src := "allow group:SRE -> root@*\ndeny * -> *@{env=prod}, when freeze\n"
	pol := policy(t, src)
	req := eval.Request{User: sreUser(), Host: prodHost(), Account: "root"}

	d, err := eval.Decide(pol, req, time.Now(), flagsFrom(map[string]bool{"freeze": true}), noFacts)
	require.NoError(t, err)
	require.Equal(t, eval.Deny, d.Outcome)

	d, err = eval.Decide(pol, req, time.Now(), flagsFrom(map[string]bool{"freeze": false}), noFacts)
	require.NoError(t, err)
	require.Equal(t, eval.Issue, d.Outcome)
}

func TestAllowWhenFlagDropsOut(t *testing.T) {
	src := "allow group:SRE -> root@*, when maintenance\n"
	pol := policy(t, src)
	req := eval.Request{User: sreUser(), Host: prodHost(), Account: "root"}

	d, err := eval.Decide(pol, req, time.Now(), flagsFrom(map[string]bool{"maintenance": false}), noFacts)
	require.NoError(t, err)
	require.Equal(t, eval.Deny, d.Outcome, "failed when is a non-match, not pending")

	d, err = eval.Decide(pol, req, time.Now(), flagsFrom(map[string]bool{"maintenance": true}), noFacts)
	require.NoError(t, err)
	require.Equal(t, eval.Issue, d.Outcome)
}

func TestUntilStopsMatchingAtTheInstant(t *testing.T) {
	src := "allow group:SRE -> root@*, until \"2026-08-31T22:00Z\"\n"
	pol := policy(t, src)
	req := eval.Request{User: sreUser(), Host: prodHost(), Account: "root"}
	boundary := time.Date(2026, 8, 31, 22, 0, 0, 0, time.UTC)

	d, err := eval.Decide(pol, req, boundary.Add(-time.Second), noFlags, noFacts)
	require.NoError(t, err)
	require.Equal(t, eval.Issue, d.Outcome)

	// The rule stops matching AT the instant.
	d, err = eval.Decide(pol, req, boundary, noFlags, noFacts)
	require.NoError(t, err)
	require.Equal(t, eval.Deny, d.Outcome)

	d, err = eval.Decide(pol, req, boundary.Add(time.Second), noFlags, noFacts)
	require.NoError(t, err)
	require.Equal(t, eval.Deny, d.Outcome)
}

// ── requirements ────────────────────────────────────────────────────

func TestRequireSatisfiedIssues(t *testing.T) {
	src := "allow group:SRE -> root@*, require [oncall, mfa]\n"
	d, err := eval.Decide(policy(t, src),
		eval.Request{User: sreUser(), Host: prodHost(), Account: "root"},
		time.Now(), noFlags,
		factsFrom(map[string]eval.FactState{"oncall": eval.FactSatisfied, "mfa": eval.FactSatisfied}))
	require.NoError(t, err)
	require.Equal(t, eval.Issue, d.Outcome)
}

func TestRequirePendingPends(t *testing.T) {
	src := "allow group:SRE -> root@*, require [oncall, approval]\n"
	d, err := eval.Decide(policy(t, src),
		eval.Request{User: sreUser(), Host: prodHost(), Account: "root"},
		time.Now(), noFlags,
		factsFrom(map[string]eval.FactState{"oncall": eval.FactSatisfied, "approval": eval.FactPending}))
	require.NoError(t, err)
	require.Equal(t, eval.Pending, d.Outcome)
	require.Equal(t, []string{"approval"}, d.PendingOn)
}

func TestRequireUnsatisfiedRulesTheAllowOut(t *testing.T) {
	src := "allow group:SRE -> root@*, require oncall\n"
	d, err := eval.Decide(policy(t, src),
		eval.Request{User: sreUser(), Host: prodHost(), Account: "root"},
		time.Now(), noFlags,
		factsFrom(map[string]eval.FactState{"oncall": eval.FactUnsatisfied}))
	require.NoError(t, err)
	require.Equal(t, eval.Deny, d.Outcome, "unsatisfied neither issues nor pends")
}

// Any single allow with all requirements satisfied issues, even while
// another surviving allow pends.
func TestOneSatisfiedAllowBeatsAPendingOne(t *testing.T) {
	src := "allow group:SRE -> root@*, require approval\nallow group:SRE -> root@{env=prod}\n"
	d, err := eval.Decide(policy(t, src),
		eval.Request{User: sreUser(), Host: prodHost(), Account: "root"},
		time.Now(), noFlags,
		factsFrom(map[string]eval.FactState{"approval": eval.FactPending}))
	require.NoError(t, err)
	require.Equal(t, eval.Issue, d.Outcome)
}

// ── TTL combination ─────────────────────────────────────────────────

func TestTTLCombinesByMinimum(t *testing.T) {
	src := "allow group:SRE -> root@*, ttl 10m\nallow type:employee -> root@*, ttl 2m\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)
	require.Equal(t, 2*time.Minute, d.TTL)
}

func TestNoTTLMeansDeploymentDefault(t *testing.T) {
	d := decide(t, "allow group:SRE -> root@*\n", eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)
	require.Zero(t, d.TTL)
}

// A rule without ttl does not drag the minimum to zero.
func TestUnsetTTLDoesNotParticipateInMinimum(t *testing.T) {
	src := "allow group:SRE -> root@*, ttl 5m\nallow type:employee -> root@*\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)
	require.Equal(t, 5*time.Minute, d.TTL)
}

// ── host and account matching detail ────────────────────────────────

func TestHostGlobStarStopsAtLabelBoundary(t *testing.T) {
	src := "allow * -> root@web-*\n"
	h := &eval.Host{Name: "web-1.example.com"}
	d := decide(t, src, eval.Request{User: sreUser(), Host: h, Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
}

func TestHostGlobMatchesWithinLabel(t *testing.T) {
	src := "allow * -> root@web-*.example.com\n"
	h := &eval.Host{Name: "web-1.example.com"}
	d := decide(t, src, eval.Request{User: sreUser(), Host: h, Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)
}

func TestHostGlobDoublestarCrossesLabels(t *testing.T) {
	src := "allow * -> root@**.controlplane.internal\n"
	for _, name := range []string{"controlplane.internal", "api.controlplane.internal", "blue.api.controlplane.internal"} {
		d := decide(t, src, eval.Request{User: sreUser(), Host: &eval.Host{Name: name}, Account: "root"})
		require.Equal(t, eval.Issue, d.Outcome, name)
	}
}

func TestLabelSelectorEntriesAND(t *testing.T) {
	src := "allow * -> root@{env=prod, role=db}\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)

	web := &eval.Host{Name: "web-1", Labels: map[string]string{"env": "prod", "role": "web"}}
	d = decide(t, src, eval.Request{User: sreUser(), Host: web, Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
}

func TestAccountGlob(t *testing.T) {
	src := "allow * -> deploy-?@*\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "deploy-1"})
	require.Equal(t, eval.Issue, d.Outcome)
	d = decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "deploy-12"})
	require.Equal(t, eval.Deny, d.Outcome)
}

func TestUserIDMatcher(t *testing.T) {
	src := "allow id:\"alice@example.com\" -> root@*\n"
	d := decide(t, src, eval.Request{User: sreUser(), Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Issue, d.Outcome)

	bob := &eval.User{ID: "bob@example.com", Active: true}
	d = decide(t, src, eval.Request{User: bob, Host: prodHost(), Account: "root"})
	require.Equal(t, eval.Deny, d.Outcome)
}

// ── fail closed ─────────────────────────────────────────────────────

func TestFlagErrorFailsClosed(t *testing.T) {
	src := "deny * -> *@*, when freeze\nallow * -> *@*\n"
	boom := errors.New("flag store down")
	_, err := eval.Decide(policy(t, src),
		eval.Request{User: sreUser(), Host: prodHost(), Account: "root"},
		time.Now(),
		func(string) (bool, error) { return false, boom }, noFacts)
	require.ErrorIs(t, err, boom)
}

func TestFactErrorFailsClosed(t *testing.T) {
	src := "allow * -> *@*, require mfa\n"
	boom := errors.New("handler crashed")
	_, err := eval.Decide(policy(t, src),
		eval.Request{User: sreUser(), Host: prodHost(), Account: "root"},
		time.Now(), noFlags,
		func(string) (eval.FactState, error) { return eval.FactUnknown, boom })
	require.ErrorIs(t, err, boom)
}
