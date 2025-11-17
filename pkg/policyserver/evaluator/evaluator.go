package evaluator

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/config"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
)

// Evaluator implements policyserver.PolicyEvaluator using OIDC token validation
// and tag-based authorization
type Evaluator struct {
	config    *config.PolicyConfig
	validator *oidc.Validator
}

// New creates a new policy evaluator
func New(ctx context.Context, cfg *config.PolicyConfig) (*Evaluator, error) {
	// Create OIDC validator
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: cfg.OIDC,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC validator: %w", err)
	}

	return &Evaluator{
		config:    cfg,
		validator: validator,
	}, nil
}

// Evaluate implements policyserver.PolicyEvaluator
func (e *Evaluator) Evaluate(token string, conn policy.Connection) (*policyserver.Response, error) {
	// Validate OIDC token
	claims, err := e.validator.Validate(context.Background(), token)
	if err != nil {
		return nil, policyserver.Unauthorized(fmt.Sprintf("Invalid token: %v", err))
	}

	// Extract user identity
	identity := claims.Identity

	// Get user's tags
	userTags, exists := e.config.Users[identity]
	if !exists {
		return nil, policyserver.Forbidden(fmt.Sprintf("User %s not in users list", identity))
	}

	// Get requested principal (the SSH username they're trying to login as)
	requestedPrincipal := conn.RemoteUser

	// Check if there's a host-specific policy
	if hostPolicy, exists := e.config.Hosts[conn.RemoteHost]; exists {
		return e.evaluateHostPolicy(identity, requestedPrincipal, userTags, conn, hostPolicy)
	}

	// Use global policy
	return e.evaluateGlobalPolicy(identity, requestedPrincipal, userTags, conn)
}

// evaluateHostPolicy evaluates policy for a specific host
func (e *Evaluator) evaluateHostPolicy(identity string, requestedPrincipal string, userTags []string, conn policy.Connection, hostPolicy *config.HostPolicy) (*policyserver.Response, error) {
	// Check if user is authorized for the requested principal on this host
	if allowedTags, exists := hostPolicy.Allow[requestedPrincipal]; exists {
		if e.hasAnyTag(userTags, allowedTags) {
			return e.buildResponse(identity, []string{requestedPrincipal}, hostPolicy.Expiration, hostPolicy.Extensions, conn.RemoteHost)
		}
	}

	// Fall back to global defaults if no host-specific rule
	if e.config.Defaults != nil && e.config.Defaults.Allow != nil {
		if allowedTags, exists := e.config.Defaults.Allow[requestedPrincipal]; exists {
			if e.hasAnyTag(userTags, allowedTags) {
				return e.buildResponse(identity, []string{requestedPrincipal}, hostPolicy.Expiration, hostPolicy.Extensions, conn.RemoteHost)
			}
		}
	}

	// Deny: user not authorized for this principal on this host
	return nil, policyserver.Forbidden(fmt.Sprintf("User %s not authorized for principal %s on host %s", identity, requestedPrincipal, conn.RemoteHost))
}

// evaluateGlobalPolicy evaluates global policy (no host-specific override)
func (e *Evaluator) evaluateGlobalPolicy(identity string, requestedPrincipal string, userTags []string, conn policy.Connection) (*policyserver.Response, error) {
	// Check defaults
	if e.config.Defaults != nil && e.config.Defaults.Allow != nil {
		if allowedTags, exists := e.config.Defaults.Allow[requestedPrincipal]; exists {
			if e.hasAnyTag(userTags, allowedTags) {
				return e.buildResponse(identity, []string{requestedPrincipal}, "", nil, "*")
			}
		}
	}

	// Deny: no rule allows this principal
	return nil, policyserver.Forbidden(fmt.Sprintf("User %s not authorized for principal %s", identity, requestedPrincipal))
}

// hasAnyTag checks if user has any of the allowed tags
func (e *Evaluator) hasAnyTag(userTags []string, allowedTags []string) bool {
	for _, userTag := range userTags {
		if slices.Contains(allowedTags, userTag) {
			return true
		}
	}
	return false
}

// buildResponse builds a policy response with the given parameters
func (e *Evaluator) buildResponse(identity string, principals []string, expirationOverride string, extensionsOverride map[string]string, hostPattern string) (*policyserver.Response, error) {
	// Determine expiration
	expiration := e.getExpiration(expirationOverride)

	// Determine extensions
	extensions := e.getExtensions(extensionsOverride)

	return &policyserver.Response{
		CertParams: ca.CertParams{
			Identity:   identity,
			Names:      principals,
			Expiration: expiration,
			Extensions: extensions,
		},
		Policy: policy.Policy{
			HostPattern: hostPattern,
		},
	}, nil
}

// getExpiration determines the certificate expiration duration
func (e *Evaluator) getExpiration(override string) time.Duration {
	// Use override if provided
	if override != "" {
		if d, err := time.ParseDuration(override); err == nil {
			return d
		}
	}

	// Use default from config
	if e.config.Defaults != nil && e.config.Defaults.Expiration != "" {
		if d, err := time.ParseDuration(e.config.Defaults.Expiration); err == nil {
			return d
		}
	}

	// Use hardcoded default
	d, _ := time.ParseDuration(config.DefaultExpiration())
	return d
}

// getExtensions determines the certificate extensions
func (e *Evaluator) getExtensions(override map[string]string) map[string]string {
	// Use override if provided
	if override != nil {
		return override
	}

	// Use default from config
	if e.config.Defaults != nil && e.config.Defaults.Extensions != nil {
		return e.config.Defaults.Extensions
	}

	// Use hardcoded default
	return config.DefaultExtensions()
}
