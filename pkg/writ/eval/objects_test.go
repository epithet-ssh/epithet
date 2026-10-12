package eval_test

import (
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/writ/eval"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"github.com/stretchr/testify/require"
)

func TestPredicatesMatchOneGroup(t *testing.T) {
	u := sreUser()
	u.Groups = []object.Object{
		{ID: "one", Names: []string{"ops"}, Attributes: object.Attributes{"role": {"admin"}}},
		{ID: "two", Names: []string{"ops"}, Attributes: object.Attributes{"role": {"oncall"}}},
	}
	for _, tc := range []struct {
		selector string
		want     eval.Outcome
	}{
		{"group{}", eval.Issue}, {"group:ops", eval.Issue}, {"group{id:one, role:admin}", eval.Issue},
		{"group{id:one, role:oncall}", eval.Deny}, {"group{role:admin, role:oncall}", eval.Deny},
		{"group{role:admin, role:admin}", eval.Issue},
	} {
		require.Equal(t, tc.want, decide(t, "allow "+tc.selector+" -> root@*", eval.Request{User: u, Host: prodHost(), Account: "root"}).Outcome, tc.selector)
	}
	u.Groups[0].Attributes["role"] = object.Values{"admin", "oncall"}
	require.Equal(t, eval.Issue, decide(t, "allow group{role:admin, role:oncall} -> root@*", eval.Request{User: u, Host: prodHost(), Account: "root"}).Outcome)
	u.Groups = nil
	require.Equal(t, eval.Deny, decide(t, "allow group{} -> root@*", eval.Request{User: u, Host: prodHost(), Account: "root"}).Outcome)
}

func TestMissingEmptyAndMultiValues(t *testing.T) {
	for _, tc := range []struct {
		values object.Values
		want   eval.Outcome
	}{
		{nil, eval.Deny}, {object.Values{}, eval.Deny}, {object.Values{""}, eval.Issue}, {object.Values{"other", ""}, eval.Issue},
	} {
		u := sreUser()
		u.Attributes = object.Attributes{"costCenter": tc.values}
		req := eval.Request{User: u, Host: prodHost(), Account: "root"}
		require.Equal(t, tc.want, decide(t, `allow user{costCenter:""} -> root@*`, req).Outcome)
		require.Equal(t, tc.want, decide(t, "allow * -> root@*\ndeny !user{costCenter:\"\"} -> root@*", req).Outcome)
	}
	u := sreUser()
	u.Groups = []object.Object{{Names: []string{"ops"}}}
	require.Equal(t, eval.Deny, decide(t, `allow group{id:""} -> root@*`, eval.Request{User: u, Host: prodHost(), Account: "root"}).Outcome)
}

func TestWholeHostConjunctionAndNegation(t *testing.T) {
	h := &eval.Host{Names: []string{"web.example", "private.example"}, Attributes: object.Attributes{"env": {"prod"}}}
	req := eval.Request{User: sreUser(), Host: h, Account: "root"}
	require.Equal(t, eval.Issue, decide(t, `allow * -> root@web.example{env:prod, name:private.example}`, req).Outcome)
	require.Equal(t, eval.Deny, decide(t, "allow * -> root@web.example\ndeny * -> root@private.example{env:prod}", req).Outcome)
	require.Equal(t, eval.Issue, decide(t, "allow * -> root@{}\ndeny * -> root@!private.example", req).Outcome)
}

func TestInvalidFactsCannotBeNegatedIntoAccess(t *testing.T) {
	u := sreUser()
	u.Groups = []object.Object{{Attributes: object.Attributes{"name": {"ops"}}}}
	_, err := eval.Decide(policy(t, "allow * -> *@*\ndeny !group:ops -> *@*"), eval.Request{User: u, Host: prodHost(), Account: "root"}, time.Now(), nil, nil)
	require.Error(t, err)
}
