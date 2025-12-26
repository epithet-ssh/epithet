package evaluator

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Evaluator implements policyserver.PolicyEvaluator using tag-based authorization
type Evaluator struct {
	config    *policyserver.PolicyRulesConfig
	validator *oidc.Validator
}

// New creates a new policy evaluator with a new OIDC validator
func New(ctx context.Context, cfg *policyserver.PolicyRulesConfig, tlsCfg tlsconfig.Config) (*Evaluator, *oidc.Validator, error) {
	// Create OIDC validator
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer:    cfg.OIDC.Issuer,
		ClientID:  cfg.OIDC.Audience,
		TLSConfig: tlsCfg,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OIDC validator: %w", err)
	}

	return &Evaluator{
		config:    cfg,
		validator: validator,
	}, validator, nil
}

// NewForTesting creates an evaluator without OIDC validation for unit testing.
// The Evaluate method doesn't use the validator (validation happens in the handler),
// so this is safe for testing policy logic.
func NewForTesting(cfg *policyserver.PolicyRulesConfig) *Evaluator {
	return &Evaluator{
		config: cfg,
	}
}

// Evaluate implements policyserver.PolicyEvaluator
// The identity has already been extracted from a validated token by the handler.
func (e *Evaluator) Evaluate(identity string, conn policy.Connection) (*policyserver.Response, error) {
	// Get user's tags
	userTags, exists := e.config.Users[identity]
	if !exists {
		return nil, policyserver.Forbidden(fmt.Sprintf("User %s not in users list", identity))
	}

	// Compute HostUsers mapping: for each host pattern, which users can this identity access?
	hostUsers := e.computeHostUsers(userTags)

	// For Hello requests (empty connection), just verify user has access to something
	// For regular requests, check authorization for the specific host/user
	isHelloRequest := conn.RemoteHost == "" && conn.RemoteUser == ""
	if isHelloRequest {
		// Hello request: user must have access to at least one host
		if len(hostUsers) == 0 {
			return nil, policyserver.Forbidden(fmt.Sprintf("User %s has no authorized hosts", identity))
		}
	} else {
		// Regular request: check if the requested (host, user) is authorized
		if !e.isAuthorized(hostUsers, conn) {
			return nil, policyserver.Forbidden(fmt.Sprintf("User %s not authorized for %s@%s", identity, conn.RemoteUser, conn.RemoteHost))
		}
	}

	// Compute ALL principals this user is authorized for (for the certificate)
	authorizedPrincipals := e.computeAuthorizedPrincipals(userTags)

	// Determine expiration and extensions
	// Use host-specific settings if available, otherwise use defaults
	var expiration string
	var extensions map[string]string

	if hostPolicy, exists := e.config.Hosts[conn.RemoteHost]; exists {
		expiration = hostPolicy.Expiration
		extensions = hostPolicy.Extensions
	}

	// Build response with HostUsers mapping
	return e.buildResponseWithHostUsers(identity, authorizedPrincipals, expiration, extensions, hostUsers)
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

// computeHostUsers builds the mapping of host patterns to allowed users
// based on the user's tags and configured policies.
func (e *Evaluator) computeHostUsers(userTags []string) map[string][]string {
	hostUsers := make(map[string][]string)

	// From defaults (pattern "*")
	if e.config.Defaults != nil && e.config.Defaults.Allow != nil {
		var users []string
		for principal, allowedTags := range e.config.Defaults.Allow {
			if e.hasAnyTag(userTags, allowedTags) {
				users = append(users, principal)
			}
		}
		if len(users) > 0 {
			slices.Sort(users)
			hostUsers["*"] = users
		}
	}

	// From host-specific policies
	for hostname, hostPolicy := range e.config.Hosts {
		if hostPolicy.Allow != nil {
			var users []string
			for principal, allowedTags := range hostPolicy.Allow {
				if e.hasAnyTag(userTags, allowedTags) {
					users = append(users, principal)
				}
			}
			if len(users) > 0 {
				slices.Sort(users)
				hostUsers[hostname] = users
			}
		}
	}

	return hostUsers
}

// isAuthorized checks if the connection is allowed by the hostUsers mapping
func (e *Evaluator) isAuthorized(hostUsers map[string][]string, conn policy.Connection) bool {
	for pattern, users := range hostUsers {
		matched, err := filepath.Match(pattern, conn.RemoteHost)
		if err != nil || !matched {
			continue
		}
		if slices.Contains(users, conn.RemoteUser) {
			return true
		}
	}
	return false
}

// buildResponseWithHostUsers builds a policy response with HostUsers mapping
func (e *Evaluator) buildResponseWithHostUsers(identity string, principals []string, expirationOverride string, extensionsOverride map[string]string, hostUsers map[string][]string) (*policyserver.Response, error) {
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
			HostUsers: hostUsers,
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
	d, _ := time.ParseDuration(policyserver.DefaultExpiration())
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
	return policyserver.DefaultExtensions()
}
