package writpolicy

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostid"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver/inventory"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/epithet-ssh/epithet/pkg/writ/eval"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
	"github.com/stretchr/testify/require"
)

const evaluatorHostID = hostid.ID("epithet-host-v1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")

// fakeInv is an in-memory Inventory for unit tests.
type fakeInv struct {
	users map[string]*eval.User
	hosts map[string]*inventory.ResolvedHost
	err   error
}

func (f *fakeInv) LookupUser(_ context.Context, identity string) (*eval.User, error) {
	return f.users[identity], f.err
}

func (f *fakeInv) LookupHost(_ context.Context, name string) (*inventory.ResolvedHost, error) {
	return f.hosts[name], f.err
}

func testInv() *fakeInv {
	return &fakeInv{
		users: map[string]*eval.User{
			"alice@example.com": {ID: "alice@example.com", Active: true, Groups: []string{"SRE"}, Type: "employee"},
		},
		hosts: map[string]*inventory.ResolvedHost{
			"prod-db-1": {Policy: eval.Host{Name: "prod-db-1", Labels: map[string]string{"env": "prod"}}},
		},
	}
}

func mustPolicy(t *testing.T, src string) *il.Policy {
	t.Helper()
	pol, diags := writ.Load(src)
	require.NotNil(t, pol, "policy failed to load: %v", diags)
	return pol
}

func conn(account, host string) policy.Connection {
	return policy.Connection{RemoteHost: host, RemoteUser: account, Port: 22}
}

func TestIssueMapsToCertParams(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@{env=prod}\n")
	e := NewForTesting(pol, testInv())
	expiry := time.Now().Add(2 * time.Minute)

	resp, err := e.Evaluate(context.Background(), "alice@example.com", expiry, conn("root", "prod-db-1"))
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", resp.CertParams.Identity)
	require.Equal(t, []string{"root"}, resp.CertParams.Names, "exactly one principal: the requested account")
	require.Equal(t, expiry, resp.CertParams.NotAfter, "cert clamped to token expiry")
	require.Equal(t, 5*time.Minute, resp.CertParams.Expiration, "deployment default TTL")
	require.Contains(t, resp.CertParams.Extensions, "permit-pty")
}

func TestIssueDerivesHashedPrincipal(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@{env=prod}\n")
	inv := testInv()
	inv.hosts["prod-db-1"].PrincipalMode = inventory.EpithetPrincipalV1
	inv.hosts["prod-db-1"].HostID = evaluatorHostID
	e := NewForTesting(pol, inv)

	resp, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	require.NoError(t, err)
	require.Equal(t,
		[]string{"epithet-principal-v1-_f8q1Ui1SZlMWCXVBJueB_F3OZzcXTaHIziX1PPULSw"},
		resp.CertParams.Names)
}

func TestIssueHashedPrincipalWithoutHostIDFailsClosed(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@{env=prod}\n")
	inv := testInv()
	inv.hosts["prod-db-1"].PrincipalMode = inventory.EpithetPrincipalV1
	e := NewForTesting(pol, inv)

	_, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	require.ErrorContains(t, err, "invalid host ID")
	var perr *wire.PolicyError
	require.False(t, errors.As(err, &perr), "issuance configuration errors are 500s, not policy denials")
}

func TestIssueUnknownPrincipalModeFailsClosed(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@{env=prod}\n")
	inv := testInv()
	inv.hosts["prod-db-1"].PrincipalMode = "mystery"
	e := NewForTesting(pol, inv)

	_, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	require.ErrorContains(t, err, `unknown principal mode "mystery"`)
}

func TestRuleTTLOverridesDefault(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@{env=prod}, ttl 2m\n")
	e := NewForTesting(pol, testInv())
	resp, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	require.NoError(t, err)
	require.Equal(t, 2*time.Minute, resp.CertParams.Expiration)
}

func TestOptionsOverrideDeploymentDefaults(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@{env=prod}\n")
	e, warnings, err := New(pol, testInv(), nil, Options{
		DefaultTTL: 10 * time.Minute,
		Extensions: map[string]string{"permit-pty": ""},
	})
	require.NoError(t, err)
	require.Empty(t, warnings)
	resp, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, resp.CertParams.Expiration)
	require.Equal(t, map[string]string{"permit-pty": ""}, resp.CertParams.Extensions)
}

func TestUnknownUserIsForbidden(t *testing.T) {
	pol := mustPolicy(t, "allow * -> *@*\n")
	e := NewForTesting(pol, testInv())
	_, err := e.Evaluate(context.Background(), "nobody@example.com", time.Now(), conn("root", "prod-db-1"))
	var perr *wire.PolicyError
	require.ErrorAs(t, err, &perr)
	require.Equal(t, http.StatusForbidden, perr.StatusCode)
}

func TestUnknownHostIsForbidden(t *testing.T) {
	pol := mustPolicy(t, "allow * -> *@*\n")
	e := NewForTesting(pol, testInv())
	_, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "mystery-host"))
	var perr *wire.PolicyError
	require.ErrorAs(t, err, &perr)
	require.Equal(t, http.StatusForbidden, perr.StatusCode)
}

// The requested host name is lowercased before the inventory lookup.
func TestHostNameLowercasedAtRequest(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@prod-db-1\n")
	e := NewForTesting(pol, testInv())
	_, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "PROD-DB-1"))
	require.NoError(t, err)
}

func TestDenyRuleNamesItselfInMessage(t *testing.T) {
	pol := mustPolicy(t, "allow * -> *@*\ndeny type:employee -> root@{env=prod}, label \"no-emp-root\"\n")
	e := NewForTesting(pol, testInv())
	_, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	var perr *wire.PolicyError
	require.ErrorAs(t, err, &perr)
	require.Equal(t, http.StatusForbidden, perr.StatusCode)
	require.Contains(t, perr.Message, "no-emp-root")
}

func TestInventoryErrorFailsClosed(t *testing.T) {
	pol := mustPolicy(t, "allow * -> *@*\n")
	inv := testInv()
	inv.err = errors.New("database down")
	e := NewForTesting(pol, inv)
	_, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	require.Error(t, err)
	var perr *wire.PolicyError
	require.False(t, errors.As(err, &perr), "an inventory failure is a 500, not a policy denial")
}

// ── registry validation ─────────────────────────────────────────────

func TestUnknownRequirementFailsAtConstruction(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@*, require oncall, label \"sre-root\"\n")
	_, _, err := New(pol, testInv(), &Registry{}, Options{})
	require.ErrorContains(t, err, "unknown requirement")
	require.ErrorContains(t, err, "oncall")
	require.ErrorContains(t, err, "sre-root")
}

func TestUnknownFlagAndNotifyFailAtConstruction(t *testing.T) {
	pol := mustPolicy(t, "deny * -> *@*, when freeze, notify \"alerts\"\n")
	_, _, err := New(pol, testInv(), &Registry{}, Options{})
	require.ErrorContains(t, err, "unknown flag")
	require.ErrorContains(t, err, "freeze")
	require.ErrorContains(t, err, "unknown notify target")
	require.ErrorContains(t, err, "alerts")
}

func TestUnlabeledRuleNamedByShortID(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@*, require oncall\n")
	_, _, err := New(pol, testInv(), &Registry{}, Options{})
	require.ErrorContains(t, err, il.ShortID(pol.Allows[0].ContentID()))
}

func TestPastUntilWarnsButLoads(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@*, until \"2020-01-01T00:00Z\", label \"expired\"\n")
	e, warnings, err := New(pol, testInv(), nil, Options{})
	require.NoError(t, err, "a past until is a warning, not a startup failure")
	require.Len(t, warnings, 1)
	require.Contains(t, warnings[0], "expired")
	require.Contains(t, warnings[0], "never match")
	require.NotNil(t, e)
}

// ── registered handlers ─────────────────────────────────────────────

type staticFlag bool

func (s staticFlag) Holds(context.Context, string) (bool, error) { return bool(s), nil }

type staticFact struct {
	status  FactStatus
	lastReq FactRequest
}

func (s *staticFact) Latency() Latency  { return Fast }
func (s *staticFact) SideEffects() bool { return false }
func (s *staticFact) Check(_ context.Context, req FactRequest) (FactResult, error) {
	s.lastReq = req
	return FactResult{Status: s.status}, nil
}

func TestRegisteredFlagGatesDeny(t *testing.T) {
	pol := mustPolicy(t, "allow * -> *@*\ndeny * -> *@{env=prod}, when freeze\n")
	frozen, _, err := New(pol, testInv(), &Registry{Flags: map[string]FlagSource{"freeze": staticFlag(true)}}, Options{})
	require.NoError(t, err)
	_, err = frozen.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	var perr *wire.PolicyError
	require.ErrorAs(t, err, &perr)
	require.Equal(t, http.StatusForbidden, perr.StatusCode)

	thawed, _, err := New(pol, testInv(), &Registry{Flags: map[string]FlagSource{"freeze": staticFlag(false)}}, Options{})
	require.NoError(t, err)
	_, err = thawed.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	require.NoError(t, err)
}

func TestPendingRequirementReturns202(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@*, require approval\n")
	fact := &staticFact{status: Pending}
	e, _, err := New(pol, testInv(), &Registry{Requirements: map[string]RequirementHandler{"approval": fact}}, Options{})
	require.NoError(t, err)
	_, err = e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	var perr *wire.PolicyError
	require.ErrorAs(t, err, &perr)
	require.Equal(t, http.StatusAccepted, perr.StatusCode)
	require.Contains(t, perr.Message, "approval")
	require.Equal(t, "approval", fact.lastReq.Requirement)
	require.Equal(t, "root", fact.lastReq.Account)
}

func TestSatisfiedRequirementIssues(t *testing.T) {
	pol := mustPolicy(t, "allow group:SRE -> root@*, require approval\n")
	e, _, err := New(pol, testInv(), &Registry{Requirements: map[string]RequirementHandler{"approval": &staticFact{status: Satisfied}}}, Options{})
	require.NoError(t, err)
	resp, err := e.Evaluate(context.Background(), "alice@example.com", time.Now(), conn("root", "prod-db-1"))
	require.NoError(t, err)
	require.Equal(t, []string{"root"}, resp.CertParams.Names)
}
