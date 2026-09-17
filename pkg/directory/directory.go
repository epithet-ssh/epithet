// Package directory owns managed identities, administration, and the user and
// group facts supplied to authorization.
package directory

import "context"

type User struct {
	UserName     string
	ID           string
	Active       bool
	Groups       []string
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
