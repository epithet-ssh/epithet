package evaluator

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// Evaluator implements policyserver.PolicyEvaluator using tag-based authorization.
// It can load policy either from a static config or dynamically via PolicyProvider.
type Evaluator struct {
	// For static policy (backwards compatibility).
	staticPolicy *policyserver.PolicyConfig

	// For dynamic policy loading.
	policyProvider policyserver.PolicyProvider
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
func (e *Evaluator) Evaluate(ctx context.Context, identity string, conn policy.Connection) (*wire.PolicyResponse, error) {
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

	// Single pass over the host patterns: build the HostUsers mapping (for
	// discovery), determine whether this connection is authorized, and pick up
	// the expiration/extensions override from the first matching pattern.
	hostUsers, authorized, expiration, extensions := e.evaluateHosts(cfg, userTags, conn)

	if !authorized {
		return nil, policyserver.Forbidden(fmt.Sprintf("User %s not authorized for %s@%s", identity, conn.RemoteUser, conn.RemoteHost))
	}

	// Compute ALL principals this user is authorized for (for the certificate).
	authorizedPrincipals := e.computeAuthorizedPrincipals(cfg, userTags)

	// Build response with HostUsers mapping.
	return e.buildResponseWithHostUsers(cfg, identity, authorizedPrincipals, expiration, extensions, hostUsers)
}

// computeAuthorizedPrincipals computes ALL principals the user is authorized for
// based on their tags. This checks both global defaults and all host-specific rules,
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

	// Check all host-specific rules.
	for _, hostRules := range cfg.Hosts {
		if hostRules.Allow != nil {
			for principal, allowedTags := range hostRules.Allow {
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

// sortedHostPatterns returns host patterns longest-first (ties lexicographic).
// YAML maps cannot preserve order, so pattern length is the deterministic
// specificity proxy; a longer pattern must never lose to a shorter one by
// map-iteration luck.
func sortedHostPatterns(hosts map[string]*policyserver.Rules) []string {
	patterns := make([]string, 0, len(hosts))
	for p := range hosts {
		patterns = append(patterns, p)
	}
	slices.SortFunc(patterns, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	return patterns
}

// evaluateHosts makes a single pass over the host patterns (longest-first,
// see sortedHostPatterns) to do everything that previously took three
// separate walks of cfg.Hosts:
//
//   - build hostUsers, the full pattern → allowed-users mapping used for
//     client-side discovery (every pattern the user has any access to, not
//     just the one matching this connection);
//   - determine whether conn is authorized, by checking membership in the
//     users allowed for each pattern that matches conn.RemoteHost;
//   - pick up the expiration/extensions override from the first
//     (highest-specificity) matching pattern's Rules.
func (e *Evaluator) evaluateHosts(cfg *policyserver.PolicyConfig, userTags []string, conn policy.Connection) (hostUsers map[string][]string, authorized bool, expiration string, extensions map[string]string) {
	hostUsers = make(map[string][]string)

	firstMatchFound := false
	for _, pattern := range sortedHostPatterns(cfg.Hosts) {
		hostRules := cfg.Hosts[pattern]
		usersSet := make(map[string]bool)

		// Add users from host-specific rules.
		if hostRules != nil && hostRules.Allow != nil {
			for principal, allowedTags := range hostRules.Allow {
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

		if len(usersSet) == 0 {
			continue
		}

		users := make([]string, 0, len(usersSet))
		for u := range usersSet {
			users = append(users, u)
		}
		slices.Sort(users)
		hostUsers[pattern] = users

		matched, err := doublestar.Match(pattern, conn.RemoteHost)
		if err != nil || !matched {
			continue
		}

		// Only the first (most specific) matching pattern's Rules apply to
		// expiration/extensions - later matches must not override it.
		if !firstMatchFound {
			firstMatchFound = true
			if hostRules != nil {
				if hostRules.Expiration != "" {
					expiration = hostRules.Expiration
				}
				if hostRules.Extensions != nil {
					extensions = hostRules.Extensions
				}
			}
		}

		if slices.Contains(users, conn.RemoteUser) {
			authorized = true
		}
	}

	return hostUsers, authorized, expiration, extensions
}

// buildResponseWithHostUsers builds a policy response with HostUsers mapping.
func (e *Evaluator) buildResponseWithHostUsers(cfg *policyserver.PolicyConfig, identity string, principals []string, expirationOverride string, extensionsOverride map[string]string, hostUsers map[string][]string) (*wire.PolicyResponse, error) {
	// Determine expiration.
	expiration := e.getExpiration(cfg, expirationOverride)

	// Determine extensions.
	extensions := e.getExtensions(cfg, extensionsOverride)

	return &wire.PolicyResponse{
		CertParams: wire.CertParams{
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
