package ca

import "errors"

// Error classes carry CA semantics independently of a private service's HTTP
// status. Wrapped diagnostics are for server logs, never public response bodies.
var (
	ErrInvalidAuthentication = errors.New("invalid user authentication")
	ErrAccessDenied          = errors.New("access denied")
	ErrAuthorizationPending  = errors.New("authorization pending")
	ErrDependency            = errors.New("CA dependency failed")
	ErrInvalidPublicKey      = errors.New("invalid public key")
)
