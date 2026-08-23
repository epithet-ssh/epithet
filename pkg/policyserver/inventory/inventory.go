// Package inventory resolves the entities a writ policy matches
// against: users (SCIM-shaped, RFC 7643) and hosts (name + labels +
// optional account list). The interface is the pluggability seam —
// today's implementation is a static file, later ones may be databases
// or live SCIM stores, and implementations are free to synthesize hosts
// (e.g. pattern-derived labels for short-lived VMs).
package inventory

import (
	"context"

	"github.com/epithet-ssh/epithet/pkg/writ/eval"
)

// Inventory looks up users and hosts at evaluation time.
//
// A (nil, nil) return means "no such entity" — a structural non-match
// that the evaluator turns into a 403, not an error. A non-nil error
// means the lookup itself failed and the evaluation must fail closed
// (500).
type Inventory interface {
	// LookupUser resolves an OIDC-bound identity to a user by comparing
	// it byte-for-byte against the configured SCIM identity attribute
	// (default userName).
	LookupUser(ctx context.Context, identity string) (*eval.User, error)

	// LookupHost resolves a requested host name. Callers must pass the
	// name through il.HostName first; implementations may synthesize a
	// host for names they can derive attributes for.
	LookupHost(ctx context.Context, name string) (*eval.Host, error)
}
