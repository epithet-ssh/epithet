// Package directory owns managed identities, administration, and the user and
// group facts supplied to authorization.
package directory

import (
	"context"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
)

type User struct {
	UserName     string
	ID           string
	Active       bool
	Groups       []object.Object
	Names        []string
	Attributes   object.Attributes
	UserType     string
	Department   string
	Organization string
}

// Revision identifies an opaque, coherent directory snapshot. Callers may compare
// revisions for equality but must not interpret their contents.
type Revision string

// Directory resolves users within one configured identity provider. LookupUser
// returns the user and revision from one coherent snapshot. Missing users return
// nil with a nonempty revision; storage failure is an error, never a missing user.
type Directory interface {
	LookupUser(context.Context, string) (*User, Revision, error)
}

// UserLister supplies administration with all users, including inactive users,
// and their policy-visible groups from one snapshot. IDs are authentication
// identities, not provisioning resource IDs. Results are ordered by userName
// then ID; users and group slices are independent copies, with groups sorted by
// name. Authorization consumers need only Directory.LookupUser.
type UserLister interface {
	ListUserFacts(context.Context) ([]User, Revision, error)
}

// Facts projects this built-in directory record onto the provider contract.
// The source schema owns its field mapping; the matcher does not know SCIM.
func (u User) Facts() object.User {
	names := u.Names
	if names == nil && u.UserName != "" {
		names = []string{u.UserName}
	}
	attrs := make(object.Attributes, len(u.Attributes)+3)
	for k, v := range u.Attributes {
		attrs[k] = v
	}
	for k, v := range map[string]string{"userType": u.UserType, "department": u.Department, "organization": u.Organization} {
		if v != "" {
			attrs[k] = object.Values{v}
		}
	}
	return object.User{ID: u.ID, Names: names, UserName: u.UserName, Attributes: attrs, Groups: u.Groups}
}
