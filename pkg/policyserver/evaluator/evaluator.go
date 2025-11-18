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
		Issuer:   cfg.OIDC.Issuer,
		ClientID: cfg.OIDC.Audience,
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

	// Compute ALL principals this user is authorized for
	authorizedPrincipals := e.computeAuthorizedPrincipals(userTags)

	// Check if the requested principal is in the authorized set
	if !slices.Contains(authorizedPrincipals, requestedPrincipal) {
		return nil, policyserver.Forbidden(fmt.Sprintf("User %s not authorized for principal %s", identity, requestedPrincipal))
	}

	// Determine expiration and extensions
	// Use host-specific settings if available, otherwise use defaults
	var expiration string
	var extensions map[string]string
	var hostPattern string

	if hostPolicy, exists := e.config.Hosts[conn.RemoteHost]; exists {
		expiration = hostPolicy.Expiration
		extensions = hostPolicy.Extensions
		hostPattern = conn.RemoteHost
	} else {
		hostPattern = "*"
	}

	// Build response with ALL authorized principals
	return e.buildResponse(identity, authorizedPrincipals, expiration, extensions, hostPattern)
}

// computeAuthorizedPrincipals computes ALL principals the user is authorized for
// based on their tags. This checks both global defaults and all host-specific policies,
// returning the union of all authorized principals.
func (e *Evaluator) computeAuthorizedPrincipals(userTags []string) []string {
	principalsSet := make(map[string]bool)

	// Check global defaults
	if e.config.Defaults != nil && e.config.Defaults.Allow != nil {
		for principal, allowedTags := range e.config.Defaults.Allow {
			if e.hasAnyTag(userTags, allowedTags) {
				principalsSet[principal] = true
			}
		}
	}

	// Check all host-specific policies
	for _, hostPolicy := range e.config.Hosts {
		if hostPolicy.Allow != nil {
			for principal, allowedTags := range hostPolicy.Allow {
				if e.hasAnyTag(userTags, allowedTags) {
					principalsSet[principal] = true
				}
			}
		}
	}

	// Convert set to sorted slice
	principals := make([]string, 0, len(principalsSet))
	for principal := range principalsSet {
		principals = append(principals, principal)
	}
	slices.Sort(principals)

	return principals
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
