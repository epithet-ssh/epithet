package scim_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/identity/oidc"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
	"github.com/epithet-ssh/epithet/pkg/inventoryserver"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/writpolicy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/stretchr/testify/require"
)

func TestProvisioningControlsCertificatesAndAdministration(t *testing.T) {
	f := newFixture(t)
	idp := oidctest.New(t)
	pub, priv, e := sshcert.GenerateKeys()
	require.NoError(t, e)
	userKey, _, e := sshcert.GenerateKeys()
	require.NoError(t, e)
	path := filepath.Join(t.TempDir(), "hosts.yaml")
	require.NoError(t, os.WriteFile(path, []byte("hosts:\n - names: [host]\n   accounts: [root]\nusers:\n - id: subject:missing\n   userName: static-fallback\n   groups: [ops]\n"), 0600))
	inv, e := inventory.NewStatic([]string{path}, inventory.WithoutUsers())
	require.NoError(t, e)
	validator, e := oidc.NewValidator(t.Context(), oidc.Config{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}})
	require.NoError(t, e)
	handler, e := inventoryserver.NewHandler(inventoryserver.Config{CAPublicKey: pub, Resolver: &inventoryserver.Resolver{Directory: f.store, Hosts: inv}, Validator: validator, Discovery: &wire.Discovery{Auth: &wire.AuthConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID}}})
	require.NoError(t, e)
	is := httptest.NewTLSServer(handler)
	defer is.Close()
	pol, diags := writ.Load("allow group:ops -> root@host\n")
	require.NotNil(t, pol, "%v", diags)
	evaluator, _, e := writpolicy.New(pol, nil, writpolicy.Options{})
	require.NoError(t, e)
	ph, e := policyserver.NewHandler(policyserver.Config{CAPublicKey: pub, Evaluator: evaluator})
	require.NoError(t, e)
	ps := httptest.NewTLSServer(ph)
	defer ps.Close()
	authority, e := ca.New(priv, ps.URL, ca.WithTLSConfig(tlsconfig.Config{Insecure: true}), ca.WithInventory(is.URL, tlsconfig.Config{Insecure: true}))
	require.NoError(t, e)
	control := &inventoryserver.Control{ManagedDirectory: f.store, Directory: f.store, Validator: validator, Admins: inventoryserver.Admins{Groups: []string{"ops"}}}
	cs := httptest.NewTLSServer(control)
	defer cs.Close()
	client, e := inventoryclient.New(cs.URL, tlsconfig.Config{Insecure: true})
	require.NoError(t, e)
	caps, e := client.Capabilities(t.Context())
	require.NoError(t, e)
	require.Contains(t, caps.Capabilities, "directory")
	require.NotContains(t, caps.Capabilities, "enroll")
	check := func(subject string, allowed bool) {
		t.Helper()
		token := idp.MintIDToken(subject, time.Now().Add(time.Hour))
		result, e := authority.Issue(t.Context(), token, policy.Connection{RemoteHost: "host", RemoteUser: "root"}, userKey)
		_, status, adminErr := client.Control(t.Context(), token, inventoryapi.ControlRequest{Action: "directory-groups"})
		if allowed {
			require.NoError(t, e)
			require.NoError(t, adminErr)
			require.Equal(t, 200, status)
			require.Equal(t, "subject:"+subject, result.Audit.ID)
			_, rev, e := f.store.LookupUser(t.Context(), "subject:"+subject)
			require.NoError(t, e)
			require.Equal(t, string(rev), result.Audit.DirectoryRevision)
		} else {
			require.Error(t, e)
			require.Nil(t, result)
			require.Error(t, adminErr)
			require.Equal(t, 403, status)
		}
	}
	a := f.request("POST", "Users", user("subject:alice", "alice", true), "", 201).Text("id")
	b := f.request("POST", "Users", user("subject:bob", "bob", true), "", 201).Text("id")
	g := f.request("POST", "Groups", group("ops", a), "", 201).Text("id")
	duplicate := f.request("POST", "Groups", group("ops", b), "", 201).Text("id")
	check("alice", true)
	check("bob", false)
	check("missing", false)
	// Rebinding uses the human OIDC identity and authorizing directory snapshot.
	bind := func(actor, target string, stale bool) {
		t.Helper()
		snapshot, e := f.store.Bindings(t.Context())
		require.NoError(t, e)
		revision := snapshot.Revision
		if stale {
			revision--
		}
		_, status, e := client.Control(t.Context(), idp.MintIDToken(actor, time.Now().Add(time.Hour)), inventoryapi.ControlRequest{Action: "directory-bind", Alias: "ops", ID: target, Revision: revision})
		if stale {
			require.Error(t, e)
			require.Equal(t, 409, status)
		} else {
			require.NoError(t, e)
			require.Equal(t, 200, status)
		}
	}
	bind("alice", duplicate, true)
	check("alice", true)
	bind("alice", duplicate, false)
	check("alice", false)
	check("bob", true)
	bind("bob", g, false)
	check("alice", true)
	check("bob", false)
	events, e := f.store.Audit(t.Context(), 0, 0)
	require.NoError(t, e)
	require.Equal(t, "subject:bob", events[len(events)-1].Actor)
	f.request("PUT", "Users/"+a, user("subject:alice", "renamed", false), "", 200)
	check("alice", false)
	f.request("PUT", "Users/"+a, user("subject:alice", "renamed", true), "", 200)
	check("alice", true)
	f.request("PUT", "Groups/"+g, group("renamed", a), "", 200)
	check("alice", true)
	f.request("PUT", "Users/"+a, user("subject:new", "renamed", true), "", 200)
	check("alice", false)
	check("new", true)
	// Neither provisioning credentials nor CA credentials can administer aliases.
	_, status, e := client.Control(t.Context(), "provisioning-secret", inventoryapi.ControlRequest{Action: "directory-groups"})
	require.Error(t, e)
	require.Equal(t, 401, status)
	f.request("DELETE", "Users/"+a, "", "", 204)
	check("new", false)
	f.request("POST", "Users", user("subject:new", "renamed", true), "", 201)
	check("new", false)
}

func TestBoundGroupsPreserveDenyAndNegatedSelectorSemantics(t *testing.T) {
	f := newFixture(t)
	a := f.request("POST", "Users", user("alice", "alice", true), "", 201).Text("id")
	b := f.request("POST", "Users", user("bob", "bob", true), "", 201).Text("id")
	g := f.request("POST", "Groups", group("ops", a), "", 201).Text("id")
	f.request("POST", "Groups", group("ops", b), "", 201)
	for _, renamed := range []bool{false, true} {
		if renamed {
			f.request("PUT", "Groups/"+g, group("new-name", a), "", 200)
		}
		for _, tc := range []struct {
			rule       string
			alice, bob bool
		}{
			{"allow * -> root@host\ndeny group:ops -> root@host\n", false, true},
			{"allow * -> root@host\ndeny !group:ops -> root@host\n", true, false},
		} {
			pol, diags := writ.Load(tc.rule)
			require.NotNil(t, pol, "%v", diags)
			evaluator, _, e := writpolicy.New(pol, nil, writpolicy.Options{})
			require.NoError(t, e)
			for _, id := range []string{"alice", "bob"} {
				u := f.facts(id)
				active := u.Active
				facts := &wire.PolicyFacts{Authentication: facts.Authentication{ID: id, ExpiresAt: time.Now().Add(time.Hour)}, Target: "host", User: &facts.User{ID: id, UserName: u.UserName, Groups: u.Groups, Active: &active}, Host: &facts.HostResource{Names: []string{"host"}, Accounts: []string{"root"}}}
				_, e = evaluator.Evaluate(t.Context(), policy.Connection{RemoteHost: "host", RemoteUser: "root"}, facts)
				allowed := tc.alice
				if id == "bob" {
					allowed = tc.bob
				}
				if allowed {
					require.NoError(t, e)
				} else {
					require.Error(t, e)
				}
			}
		}
	}
}
