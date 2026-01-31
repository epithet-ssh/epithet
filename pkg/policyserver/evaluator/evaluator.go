package evaluator

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// Evaluator implements policyserver.PolicyEvaluator using tag-based authorization.
// It can load policy either from a static config or dynamically via PolicyProvider.
type Evaluator struct {
	// For static policy (backwards compatibility).
	staticPolicy *policyserver.PolicyConfig

	// For dynamic policy loading.
	policyProvider policyserver.PolicyProvider

	validator *oidc.Validator
}

// New creates a new policy evaluator with a new OIDC validator.
// This constructor uses static policy from PolicyRulesConfig for backwards compatibility.
func New(ctx context.Context, cfg *policyserver.PolicyRulesConfig, tlsCfg tlsconfig.Config) (*Evaluator, *oidc.Validator, error) {
	// Create OIDC validator.
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer:    cfg.OIDC.Issuer,
		ClientID:  cfg.OIDC.ClientID,
		TLSConfig: tlsCfg,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OIDC validator: %w", err)
	}

	return &Evaluator{
		staticPolicy: cfg.ExtractPolicyConfig(),
		validator:    validator,
	}, validator, nil
}

// NewWithProvider creates a new policy evaluator that loads policy dynamically.
func NewWithProvider(ctx context.Context, serverCfg *policyserver.ServerConfig, provider policyserver.PolicyProvider, tlsCfg tlsconfig.Config) (*Evaluator, *oidc.Validator, error) {
	// Create OIDC validator.
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer:    serverCfg.OIDC.Issuer,
		ClientID:  serverCfg.OIDC.ClientID,
		TLSConfig: tlsCfg,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OIDC validator: %w", err)
	}

	return &Evaluator{
		policyProvider: provider,
		validator:      validator,
	}, validator, nil
}

// NewForTesting creates an evaluator without OIDC validation for unit testing.
// The Evaluate method doesn't use the validator (validation happens in the handler),
// so this is safe for testing policy logic.
func NewForTesting(cfg *policyserver.PolicyRulesConfig) *Evaluator {
	return &Evaluator{
		staticPolicy: cfg.ExtractPolicyConfig(),
	}
}

// NewForTestingWithProvider creates an evaluator with a policy provider for testing.
func NewForTestingWithProvider(provider policyserver.PolicyProvider) *Evaluator {
	return &Evaluator{
		policyProvider: provider,
	}
}

// getPolicy returns the current policy, either from static config or dynamic provider.
func (e *Evaluator) getPolicy(ctx context.Context) (*policyserver.PolicyConfig, error) {
	if e.policyProvider != nil {
		return e.policyProvider.GetPolicy(ctx)
	}
	return e.staticPolicy, nil
}

// Evaluate implements policyserver.PolicyEvaluator.
// The identity has already been extracted from a validated token by the handler.
func (e *Evaluator) Evaluate(ctx context.Context, identity string, conn policy.Connection) (*policyserver.Response, error) {
	// Load current policy.
	cfg, err := e.getPolicy(ctx)
	if err != nil {
		return nil, policyserver.InternalError(fmt.Sprintf("failed to load policy: %v", err))
	}

	// Get user's tags.
	userTags, exists := cfg.Users[identity]
	if !exists {
		return nil, policyserver.Forbidden(fmt.Sprintf("User %s not in users list", identity))
	}

	// Compute HostUsers mapping: for each host pattern, which users can this identity access?
	hostUsers := e.computeHostUsers(cfg, userTags)

	// For Hello requests (empty connection), just verify user has access to something.
	// For regular requests, check authorization for the specific host/user.
	isHelloRequest := conn.RemoteHost == "" && conn.RemoteUser == ""
	if isHelloRequest {
		// Hello request: user must have access to at least one host.
		if len(hostUsers) == 0 {
			return nil, policyserver.Forbidden(fmt.Sprintf("User %s has no authorized hosts", identity))
		}
	} else {
		// Regular request: check if the requested (host, user) is authorized.
		if !e.isAuthorized(hostUsers, conn) {
			return nil, policyserver.Forbidden(fmt.Sprintf("User %s not authorized for %s@%s", identity, conn.RemoteUser, conn.RemoteHost))
		}
	}

	// Compute ALL principals this user is authorized for (for the certificate).
	authorizedPrincipals := e.computeAuthorizedPrincipals(cfg, userTags)

	// Determine expiration and extensions.
	// Find matching host pattern and use its settings, otherwise use defaults.
	var expiration string
	var extensions map[string]string

	for pattern, hostPolicy := range cfg.Hosts {
		matched, err := doublestar.Match(pattern, conn.RemoteHost)
		if err != nil || !matched {
			continue
		}
		if hostPolicy != nil {
			if hostPolicy.Expiration != "" {
				expiration = hostPolicy.Expiration
			}
			if hostPolicy.Extensions != nil {
				extensions = hostPolicy.Extensions
			}
		}
		break // Use first match.
	}

	// Build response with HostUsers mapping.
	return e.buildResponseWithHostUsers(cfg, identity, authorizedPrincipals, expiration, extensions, hostUsers)
}

// computeAuthorizedPrincipals computes ALL principals the user is authorized for
// based on their tags. This checks both global defaults and all host-specific policies,
// returning the union of all authorized principals.
func (e *Evaluator) computeAuthorizedPrincipals(cfg *policyserver.PolicyConfig, userTags []string) []string {
	principalsSet := make(map[string]bool)

	// Check global defaults.
	if cfg.Defaults != nil && cfg.Defaults.Allow != nil {
		for principal, allowedTags := range cfg.Defaults.Allow {
			if e.hasAnyTag(userTags, allowedTags) {
				principalsSet[principal] = true
			}
		}
	}

	// Check all host-specific policies.
	for _, hostPolicy := range cfg.Hosts {
		if hostPolicy.Allow != nil {
			for principal, allowedTags := range hostPolicy.Allow {
				if e.hasAnyTag(userTags, allowedTags) {
					principalsSet[principal] = true
				}
			}
		}
	}

	// Convert set to sorted slice.
	principals := make([]string, 0, len(principalsSet))
	for principal := range principalsSet {
		principals = append(principals, principal)
	}
	slices.Sort(principals)

	return principals
}

// hasAnyTag checks if user has any of the allowed tags.
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
//
// Host patterns come from the Hosts config only - defaults.Allow is merged
// into each host pattern but does NOT create a wildcard "*" pattern.
// This ensures that a host must match an explicit pattern in Hosts before
// any authorization is granted.
func (e *Evaluator) computeHostUsers(cfg *policyserver.PolicyConfig, userTags []string) map[string][]string {
	hostUsers := make(map[string][]string)

	// For each host pattern, compute allowed users from BOTH the host policy AND defaults.
	for hostname, hostPolicy := range cfg.Hosts {
		usersSet := make(map[string]bool)

		// Add users from host-specific policy.
		if hostPolicy != nil && hostPolicy.Allow != nil {
			for principal, allowedTags := range hostPolicy.Allow {
				if e.hasAnyTag(userTags, allowedTags) {
					usersSet[principal] = true
				}
			}
		}

		// Add users from defaults (applied to ALL host patterns).
		if cfg.Defaults != nil && cfg.Defaults.Allow != nil {
			for principal, allowedTags := range cfg.Defaults.Allow {
				if e.hasAnyTag(userTags, allowedTags) {
					usersSet[principal] = true
				}
			}
		}

		if len(usersSet) > 0 {
			users := make([]string, 0, len(usersSet))
			for u := range usersSet {
				users = append(users, u)
			}
			slices.Sort(users)
			hostUsers[hostname] = users
		}
	}

	return hostUsers
}

// isAuthorized checks if the connection is allowed by the hostUsers mapping.
func (e *Evaluator) isAuthorized(hostUsers map[string][]string, conn policy.Connection) bool {
	for pattern, users := range hostUsers {
		matched, err := doublestar.Match(pattern, conn.RemoteHost)
		if err != nil || !matched {
			continue
		}
		if slices.Contains(users, conn.RemoteUser) {
			return true
		}
	}
	return false
}

// buildResponseWithHostUsers builds a policy response with HostUsers mapping.
func (e *Evaluator) buildResponseWithHostUsers(cfg *policyserver.PolicyConfig, identity string, principals []string, expirationOverride string, extensionsOverride map[string]string, hostUsers map[string][]string) (*policyserver.Response, error) {
	// Determine expiration.
	expiration := e.getExpiration(cfg, expirationOverride)

	// Determine extensions.
	extensions := e.getExtensions(cfg, extensionsOverride)

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

// getExpiration determines the certificate expiration duration.
func (e *Evaluator) getExpiration(cfg *policyserver.PolicyConfig, override string) time.Duration {
	// Use override if provided.
	if override != "" {
		if d, err := time.ParseDuration(override); err == nil {
			return d
		}
	}

	// Use default from config.
	if cfg.Defaults != nil && cfg.Defaults.Expiration != "" {
		if d, err := time.ParseDuration(cfg.Defaults.Expiration); err == nil {
			return d
		}
	}

	// Use hardcoded default.
	d, _ := time.ParseDuration(policyserver.DefaultExpiration())
	return d
}

// getExtensions determines the certificate extensions.
func (e *Evaluator) getExtensions(cfg *policyserver.PolicyConfig, override map[string]string) map[string]string {
	// Use override if provided.
	if override != nil {
		return override
	}

	// Use default from config.
	if cfg.Defaults != nil && cfg.Defaults.Extensions != nil {
		return cfg.Defaults.Extensions
	}

	// Use hardcoded default.
	return policyserver.DefaultExtensions()
}
