package policyserver

// Discovery types are defined in policyserver.go (DiscoveryResponse).
// The old client-facing discovery handler with auth/unauth split has been
// removed — the CA now serves /discovery to clients, fetching from the
// policy server's GET / endpoint.
