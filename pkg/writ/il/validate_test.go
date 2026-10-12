package il

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidateEverySelectorPosition(t *testing.T) {
	for _, deny := range []bool{false, true} {
		for _, position := range []string{"user", "account", "host"} {
			p := Policy{Schema: Schema, Allows: []AllowRule{specAllow()}, Denies: []DenyRule{specDeny()}}
			var selector *Selector
			if deny {
				switch position {
				case "user":
					selector = &p.Denies[0].Users.Selector
				case "account":
					selector = &p.Denies[0].Accounts.Selector
				case "host":
					selector = &p.Denies[0].Hosts.Selector
				}
			} else {
				switch position {
				case "user":
					selector = &p.Allows[0].Users
				case "account":
					selector = &p.Allows[0].Accounts
				case "host":
					selector = &p.Allows[0].Hosts
				}
			}
			selector.Kind = "obsolete"
			require.Error(t, p.Validate(), "deny=%v position=%s", deny, position)
		}
	}
	for _, schema := range []int{0, 1, 2, 4} {
		require.Error(t, (&Policy{Schema: schema}).Validate())
	}
	for _, s := range []Selector{
		{Kind: Account, Predicates: []Predicate{{Attribute: "id", Value: "root"}}},
		{Kind: Account, Predicates: []Predicate{{Attribute: "name", Value: "root"}, {Attribute: "name", Value: "admin"}}},
	} {
		rule := specAllow()
		rule.Accounts = s
		require.Error(t, (&Policy{Schema: Schema, Allows: []AllowRule{rule}}).Validate())
	}
	for _, value := range []string{"UPPER", "host**.example"} {
		rule := specAllow()
		rule.Hosts = Selector{Kind: Host, Predicates: []Predicate{{Attribute: "name", Value: value}}}
		require.Error(t, (&Policy{Schema: Schema, Allows: []AllowRule{rule}}).Validate())
	}
}
