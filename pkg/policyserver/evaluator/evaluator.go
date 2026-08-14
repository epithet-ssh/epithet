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
// Policy is read once at startup from config; reload is a process restart
// (dynamic loading via URL was removed, see task 8b).
type Evaluator struct {
	policy *policyserver.PolicyConfig
}

// New creates the evaluator and its OIDC validator.
func New(ctx context.Context, serverCfg *policyserver.ServerConfig, policyCfg *policyserver.PolicyConfig, tlsCfg tlsconfig.Config) (*Evaluator, *oidc.Validator, error) {
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
		policy: policyCfg,
	}, validator, nil
}

// NewForTesting creates an evaluator without a validator.
// The Evaluate method doesn't use the validator (validation happens in the handler),
// so this is safe for testing policy logic.
func NewForTesting(policyCfg *policyserver.PolicyConfig) *Evaluator {
	return &Evaluator{
		policy: policyCfg,
	}
}

// Evaluate implements policyserver.PolicyEvaluator.
// The identity has already been extracted from a validated token by the handler.
// tokenExpiry is carried into CertParams.NotAfter so the CA can clamp the
// issued certificate's validity to the auth session's remaining lifetime.
func (e *Evaluator) Evaluate(ctx context.Context, identity string, tokenExpiry time.Time, conn policy.Connection) (*wire.PolicyResponse, error) {
	cfg := e.policy

	// Get user's tags.
	userTags, exists := cfg.Users[identity]
	if !exists {
		return nil, policyserver.Forbidden(fmt.Sprintf("User %s not in users list", identity))
	}

	// Single pass over the host patterns: determine whether this connection is
	// authorized, and pick up the expiration/extensions override from the
	// first matching pattern.
	authorized, expiration, extensions := e.evaluateHosts(cfg, userTags, conn)

	if !authorized {
		return nil, policyserver.Forbidden(fmt.Sprintf("User %s not authorized for %s@%s", identity, conn.RemoteUser, conn.RemoteHost))
	}

	// The cert carries only the principal actually requested for this
	// connection - never the union of everything the user's tags could reach
	// elsewhere in the policy (see Task 11b: authorization maps leave the
	// wire entirely, and certs become strictly per-connection).
	return e.buildResponse(cfg, identity, tokenExpiry, conn.RemoteUser, expiration, extensions), nil
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
// see sortedHostPatterns) to determine whether conn is authorized and to pick
// up the expiration/extensions override from the first (highest-specificity)
// matching pattern's Rules. A pattern that grants nobody access (merged
// host+defaults Allow is empty for every principal) is skipped entirely, so
// it can never "win" the expiration/extensions override away from a pattern
// that actually authorizes someone.
func (e *Evaluator) evaluateHosts(cfg *policyserver.PolicyConfig, userTags []string, conn policy.Connection) (authorized bool, expiration string, extensions map[string]string) {
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

		if usersSet[conn.RemoteUser] {
			authorized = true
		}
	}

	return authorized, expiration, extensions
}

// buildResponse builds the policy response for an authorized connection. The
// certificate names only conn.RemoteUser - see the comment on Evaluate.
func (e *Evaluator) buildResponse(cfg *policyserver.PolicyConfig, identity string, tokenExpiry time.Time, remoteUser string, expirationOverride string, extensionsOverride map[string]string) *wire.PolicyResponse {
	// Determine expiration.
	expiration := e.getExpiration(cfg, expirationOverride)

	// Determine extensions.
	extensions := e.getExtensions(cfg, extensionsOverride)

	return &wire.PolicyResponse{
		CertParams: wire.CertParams{
			Identity:   identity,
			Names:      []string{remoteUser},
			Expiration: expiration,
			Extensions: extensions,
			NotAfter:   tokenExpiry,
		},
	}
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
