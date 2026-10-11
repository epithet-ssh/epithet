// Package oidc owns OIDC login, token verification, and Epithet identity mapping.
// Authenticate obtains credentials through browser or device login and refresh;
// callers own token state, session coordination, and progress output. Verifier
// checks tokens independently of directory mapping. Validator adds the configured
// mapping from verified claims to a directory user ID for CA and control.
// Directory lookup and authorization remain the responsibility of those services.
//
// # Service discovery lifecycle
//
// CA and control use PrepareService to validate local configuration without
// contacting the issuer. The returned configuration shares discovery state with
// its lifecycle handle, preserving the ordinary service construction interfaces.
// Services open their listeners before calling Run, so a temporary discovery
// outage does not prevent bootstrap or readiness responses.
// Run retries transient discovery failures until recovery or shutdown; permanent
// configuration, trust, and discovery metadata errors terminate initialization.
// Interactive callers use NewValidator or NewVerifier for a single attempt.
//
// Ready reports completed discovery, not current IdP reachability. Pending
// discovery returns ErrUnavailable without bypassing authentication. After
// discovery, signing-key fetching and token verification retain go-oidc's existing
// behavior. Services own the HTTP mapping of startup errors and readiness.
package oidc
