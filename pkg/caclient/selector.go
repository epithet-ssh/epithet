package caclient

import (
	"errors"
	"sort"
	"sync"
	"time"

	gobreaker "github.com/sony/gobreaker/v2"
)

// selector manages CA endpoint selection with priority-based failover and circuit breakers.
// It is not exported; it's used internally by Client.
type selector struct {
	mu sync.Mutex

	// endpoints sorted by priority (highest first)
	endpoints []CAEndpoint

	// breakers maps URL to circuit breaker
	breakers map[string]*gobreaker.CircuitBreaker[struct{}]

	// tiers groups endpoints by priority, sorted descending
	tiers [][]CAEndpoint

	// tierIndex tracks round-robin position within each tier
	tierIndex map[int]int

	cooldown time.Duration
}

// newSelector creates a selector for the given endpoints.
// The cooldown duration specifies how long a failed CA remains in circuit breaker open state.
func newSelector(endpoints []CAEndpoint, cooldown time.Duration) *selector {
	// Sort endpoints by priority descending (highest first)
	sorted := make([]CAEndpoint, len(endpoints))
	copy(sorted, endpoints)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	// Group into tiers by priority
	tiers := groupByPriority(sorted)

	// Create circuit breaker for each endpoint
	breakers := make(map[string]*gobreaker.CircuitBreaker[struct{}], len(endpoints))
	for _, ep := range endpoints {
		breakers[ep.URL] = gobreaker.NewCircuitBreaker[struct{}](gobreaker.Settings{
			Name:    ep.URL,
			Timeout: cooldown, // Time in Open state before trying again

			// Open circuit on first failure (we have multiple CAs to try)
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.ConsecutiveFailures >= 1
			},

			// Only count infrastructure failures, not auth/policy errors
			IsSuccessful: isSuccessfulForCircuitBreaker,
		})
	}

	// Initialize tier indices for round-robin
	tierIndex := make(map[int]int, len(tiers))
	for _, tier := range tiers {
		if len(tier) > 0 {
			tierIndex[tier[0].Priority] = 0
		}
	}

	return &selector{
		endpoints: sorted,
		breakers:  breakers,
		tiers:     tiers,
		tierIndex: tierIndex,
		cooldown:  cooldown,
	}
}

// groupByPriority groups sorted endpoints into tiers by priority.
// Input must be sorted by priority descending.
func groupByPriority(sorted []CAEndpoint) [][]CAEndpoint {
	if len(sorted) == 0 {
		return nil
	}

	var tiers [][]CAEndpoint
	var currentTier []CAEndpoint
	currentPriority := sorted[0].Priority

	for _, ep := range sorted {
		if ep.Priority != currentPriority {
			tiers = append(tiers, currentTier)
			currentTier = nil
			currentPriority = ep.Priority
		}
		currentTier = append(currentTier, ep)
	}
	if len(currentTier) > 0 {
		tiers = append(tiers, currentTier)
	}

	return tiers
}

// next returns the next available CA URL and its circuit breaker.
// It tries higher priority tiers first, using round-robin within each tier.
// Returns empty string and nil if all CAs are unavailable (circuit breakers open).
func (s *selector) next() (string, *gobreaker.CircuitBreaker[struct{}]) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Try each tier in priority order (highest first)
	for _, tier := range s.tiers {
		if len(tier) == 0 {
			continue
		}

		priority := tier[0].Priority
		startIdx := s.tierIndex[priority]

		// Round-robin through this tier, looking for an available CA
		for i := 0; i < len(tier); i++ {
			idx := (startIdx + i) % len(tier)
			ep := tier[idx]
			breaker := s.breakers[ep.URL]

			// Check if this CA is available (not in open state)
			if breaker.State() != gobreaker.StateOpen {
				// Advance round-robin index for next call
				s.tierIndex[priority] = (idx + 1) % len(tier)
				return ep.URL, breaker
			}
		}
		// All CAs in this tier are unavailable, try next tier
	}

	// All CAs unavailable
	return "", nil
}

// allUnavailable returns true if all circuit breakers are in the open state.
func (s *selector) allUnavailable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, breaker := range s.breakers {
		if breaker.State() != gobreaker.StateOpen {
			return false
		}
	}
	return true
}

// isSuccessfulForCircuitBreaker determines whether an error should count as a
// circuit breaker failure. Only infrastructure errors (connection failures,
// timeouts, 5xx) trigger the circuit breaker. Auth and policy errors do not.
func isSuccessfulForCircuitBreaker(err error) bool {
	if err == nil {
		return true
	}

	// CAUnavailableError (5xx) triggers circuit breaker
	var caUnavail *CAUnavailableError
	if errors.As(err, &caUnavail) {
		return false
	}

	// Connection errors and timeouts also trigger circuit breaker
	// These are typically returned as-is from http.Client.Do
	// We check for specific error types that indicate infrastructure issues

	// Context deadline exceeded (timeout)
	if errors.Is(err, errors.ErrUnsupported) {
		// This is a placeholder - actual timeout detection happens in GetCert
		return false
	}

	// InvalidTokenError (401) - auth issue, not infrastructure
	var invalidToken *InvalidTokenError
	if errors.As(err, &invalidToken) {
		return true // Don't trip breaker
	}

	// PolicyDeniedError (403) - policy issue, not infrastructure
	var policyDenied *PolicyDeniedError
	if errors.As(err, &policyDenied) {
		return true // Don't trip breaker
	}

	// InvalidRequestError (4xx) - client issue, not infrastructure
	var invalidReq *InvalidRequestError
	if errors.As(err, &invalidReq) {
		return true // Don't trip breaker
	}

	// Unknown errors - treat as infrastructure failures to be safe
	// This includes connection refused, DNS failures, TLS errors, etc.
	return false
}
