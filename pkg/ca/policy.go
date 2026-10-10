package ca

import (
	"context"

	"github.com/epithet-ssh/epithet/pkg/wire"
)

// PolicyEvaluator decides access using validated CA-owned authentication and
// current directory/host facts. It has no storage or transport responsibility.
// It returns a positive TTL, extensions, and an optional tighter deadline.
// CA always enforces the authentication lifetime as an additional ceiling.
type PolicyEvaluator interface {
	Evaluate(context.Context, wire.Connection, *wire.PolicyFacts) (*wire.PolicyResponse, error)
}
