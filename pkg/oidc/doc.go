// Package oidc owns OIDC login, token verification, and Epithet identity mapping.
// Authenticate obtains credentials through browser or device login and refresh;
// callers own token state, session coordination, and progress output. Verifier
// checks tokens independently of directory mapping. Validator adds the configured
// mapping from verified claims to a directory user ID for CA and control.
// Directory lookup and authorization remain the responsibility of those services.
package oidc
