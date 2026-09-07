// Package directory owns the user and group facts supplied to authorization.
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

// Directory resolves users within one configured identity provider.
type Directory interface {
	LookupUser(context.Context, string) (*User, error)
}
