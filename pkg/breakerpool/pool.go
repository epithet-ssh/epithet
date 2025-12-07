// Package breakerpool provides a generic circuit breaker pool with priority-based failover.
package breakerpool

import (
	"fmt"
	"sort"
	"sync"

	gobreaker "github.com/sony/gobreaker/v2"
)

// DefaultPriority is the default priority for entries without an explicit priority.
const DefaultPriority = 100

// Entry associates state with optional per-entry circuit breaker settings.
type Entry[S any] struct {
	// State is passed to the Execute callback. This is the only required field.
	State S

	// Priority determines failover order. Higher values are tried first.
	// If zero, DefaultPriority (100) is used.
	Priority int

	// Settings overrides the pool's default gobreaker settings for this entry.
	// If nil, the pool's default settings are used.
	Settings *gobreaker.Settings
}

// Pool manages circuit breakers with priority-based failover.
// When executing operations, it tries entries in priority order (highest first),
// using round-robin within the same priority tier. If a breaker is open or trips,
// the pool tries the next available entry.
type Pool[T, S any] struct {
	mu sync.Mutex

	// entries with their state, sorted by priority (highest first)
	entries []Entry[S]

	// breakers parallel to entries (same index)
	breakers []*gobreaker.CircuitBreaker[T]

	// tiers groups entry indices by priority, sorted descending
	tiers [][]int

	// tierIndex tracks round-robin position within each priority tier
	tierIndex map[int]int
}

// New creates a new Pool with the given entries and default circuit breaker settings.
// For each entry:
//   - Uses entry.Settings if non-nil, otherwise uses defaults
//   - Uses entry.Priority if non-zero, otherwise uses DefaultPriority
func New[T, S any](entries []Entry[S], defaults gobreaker.Settings) *Pool[T, S] {
	if len(entries) == 0 {
		return &Pool[T, S]{
			entries:   nil,
			breakers:  nil,
			tiers:     nil,
			tierIndex: make(map[int]int),
		}
	}

	// Normalize priorities and create index mapping
	type indexedEntry struct {
		index    int
		priority int
	}
	indexed := make([]indexedEntry, len(entries))
	for i, e := range entries {
		priority := e.Priority
		if priority == 0 {
			priority = DefaultPriority
		}
		indexed[i] = indexedEntry{index: i, priority: priority}
	}

	// Sort by priority descending (highest first)
	sort.Slice(indexed, func(i, j int) bool {
		return indexed[i].priority > indexed[j].priority
	})

	// Build sorted entries and breakers
	sortedEntries := make([]Entry[S], len(entries))
	breakers := make([]*gobreaker.CircuitBreaker[T], len(entries))

	for i, ie := range indexed {
		e := entries[ie.index]

		// Normalize priority in the entry
		if e.Priority == 0 {
			e.Priority = DefaultPriority
		}
		sortedEntries[i] = e

		// Create circuit breaker with entry settings or defaults
		settings := defaults
		if e.Settings != nil {
			settings = *e.Settings
		}
		breakers[i] = gobreaker.NewCircuitBreaker[T](settings)
	}

	// Group into tiers by priority
	tiers := groupByPriority(sortedEntries)

	// Initialize tier indices for round-robin
	tierIndex := make(map[int]int, len(tiers))
	for _, tier := range tiers {
		if len(tier) > 0 {
			tierIndex[sortedEntries[tier[0]].Priority] = 0
		}
	}

	return &Pool[T, S]{
		entries:   sortedEntries,
		breakers:  breakers,
		tiers:     tiers,
		tierIndex: tierIndex,
	}
}

// groupByPriority groups entry indices into tiers by priority.
// Input entries must be sorted by priority descending.
// Returns slices of indices into the entries slice.
func groupByPriority[S any](entries []Entry[S]) [][]int {
	if len(entries) == 0 {
		return nil
	}

	var tiers [][]int
	var currentTier []int
	currentPriority := entries[0].Priority

	for i, e := range entries {
		if e.Priority != currentPriority {
			tiers = append(tiers, currentTier)
			currentTier = nil
			currentPriority = e.Priority
		}
		currentTier = append(currentTier, i)
	}
	if len(currentTier) > 0 {
		tiers = append(tiers, currentTier)
	}

	return tiers
}

// AllUnavailableError indicates all endpoints are unavailable.
type AllUnavailableError struct {
	LastError error
}

func (e *AllUnavailableError) Error() string {
	if e.LastError != nil {
		return fmt.Sprintf("all endpoints unavailable, last error: %v", e.LastError)
	}
	return "all endpoints unavailable"
}

func (e *AllUnavailableError) Unwrap() error {
	return e.LastError
}

// Execute runs the given function against entries in priority order.
// The function receives the entry's State and should perform the operation.
// If the operation fails with an error that trips the circuit breaker,
// Execute tries the next available entry.
// Returns AllUnavailableError if all entries are unavailable.
func (p *Pool[T, S]) Execute(fn func(S) (T, error)) (T, error) {
	var zero T
	var lastErr error

	for {
		// Get next available entry index
		idx := p.next()
		if idx < 0 {
			return zero, &AllUnavailableError{LastError: lastErr}
		}

		entry := p.entries[idx]
		breaker := p.breakers[idx]

		// Execute through the circuit breaker
		result, err := breaker.Execute(func() (T, error) {
			return fn(entry.State)
		})

		if err != nil {
			// Check if this is a circuit breaker open error
			if err == gobreaker.ErrOpenState || err == gobreaker.ErrTooManyRequests {
				// Breaker is open, try next entry
				lastErr = err
				continue
			}

			// Check if this error tripped the breaker (via IsSuccessful)
			// If it did, we should try the next entry
			// If it didn't (e.g., auth error), return immediately
			if breaker.State() == gobreaker.StateOpen {
				// Breaker tripped, try next
				lastErr = err
				continue
			}

			// Error didn't trip breaker, return it
			return zero, err
		}

		return result, nil
	}
}

// next returns the index of the next available entry.
// It tries higher priority tiers first, using round-robin within each tier.
// Returns -1 if all entries are unavailable.
func (p *Pool[T, S]) next() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try each tier in priority order (highest first)
	for _, tier := range p.tiers {
		if len(tier) == 0 {
			continue
		}

		priority := p.entries[tier[0]].Priority
		startIdx := p.tierIndex[priority]

		// Round-robin through this tier, looking for an available entry
		for i := 0; i < len(tier); i++ {
			tierPos := (startIdx + i) % len(tier)
			entryIdx := tier[tierPos]
			breaker := p.breakers[entryIdx]

			// Check if this entry is available (not in open state)
			if breaker.State() != gobreaker.StateOpen {
				// Advance round-robin index for next call
				p.tierIndex[priority] = (tierPos + 1) % len(tier)
				return entryIdx
			}
		}
		// All entries in this tier are unavailable, try next tier
	}

	// All entries unavailable
	return -1
}

// AllUnavailable returns true if all circuit breakers are in the open state.
func (p *Pool[T, S]) AllUnavailable() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.breakers) == 0 {
		return true
	}

	for _, breaker := range p.breakers {
		if breaker.State() != gobreaker.StateOpen {
			return false
		}
	}
	return true
}

// Len returns the number of entries in the pool.
func (p *Pool[T, S]) Len() int {
	return len(p.entries)
}
