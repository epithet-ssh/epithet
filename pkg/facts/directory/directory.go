// Package directory owns managed identities, administration, and the user and
// group facts supplied to authorization.
package directory

import (
	"context"

	"github.com/epithet-ssh/epithet/pkg/writ/object"
)

// Group contains the group facts supplied to authorization. Names are aliases
// for one group; ID is optional for sources without stable group identities.
// ManagedGroup holds the provisioning record, including its member IDs.
type Group struct {
	ID         string
	Names      []string
	Attributes object.Attributes
}

type User struct {
	UserName     string
	ID           string
	Active       bool
	Groups       []Group
	Names        []string
	Attributes   object.Attributes
	UserType     string
	Department   string
	Organization string
}

// Directory resolves users within one configured identity provider. LookupUser
// returns user facts. Missing users return nil; storage failure is an error,
// never a missing user.
// Read consistency and visibility of user and membership changes are backend-specific.
// The lookup key and returned User.ID are the stored user's ID. Mapping an OIDC
// claim or provisioning attribute to that ID is Epithet's responsibility.
type Directory interface {
	LookupUser(context.Context, string) (*User, error)
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
	var groups []object.Object
	if u.Groups != nil {
		groups = make([]object.Object, len(u.Groups))
		for i, g := range u.Groups {
			groups[i] = object.Object{ID: g.ID, Names: g.Names, Attributes: g.Attributes}
		}
	}
	return object.User{ID: u.ID, Names: names, UserName: u.UserName, Attributes: attrs, Groups: groups}
}
