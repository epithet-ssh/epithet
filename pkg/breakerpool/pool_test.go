package breakerpool

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gobreaker "github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/require"
)

// infraError is an error type that should trip the circuit breaker
type infraError struct{ msg string }

func (e *infraError) Error() string { return e.msg }

// authError is an error type that should NOT trip the circuit breaker
type authError struct{ msg string }

func (e *authError) Error() string { return e.msg }

// testDefaults returns default settings for tests
func testDefaults(cooldown time.Duration) gobreaker.Settings {
	return gobreaker.Settings{
		Timeout: cooldown,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 1
		},
		IsSuccessful: func(err error) bool {
			if err == nil {
				return true
			}
			var auth *authError
			if errors.As(err, &auth) {
				return true // Auth errors don't trip breaker
			}
			return false // Infrastructure errors trip breaker
		},
	}
}

// testState is a simple state type for tests
type testState struct {
	url string
}

func TestPool_Execute_SingleEntry(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}},
	}
	pool := New[string](entries, testDefaults(time.Minute))

	result, err := pool.Execute(func(s testState) (string, error) {
		require.Equal(t, "https://ca1.example.com", s.url)
		return "success", nil
	})

	require.NoError(t, err)
	require.Equal(t, "success", result)
}

func TestPool_Execute_PriorityOrder(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca-low.example.com"}, Priority: 50},
		{State: testState{url: "https://ca-high.example.com"}, Priority: 100},
	}
	pool := New[string](entries, testDefaults(time.Minute))

	// Should try high priority first
	result, err := pool.Execute(func(s testState) (string, error) {
		require.Equal(t, "https://ca-high.example.com", s.url)
		return "high", nil
	})

	require.NoError(t, err)
	require.Equal(t, "high", result)
}

func TestPool_Execute_DefaultPriority(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}},              // uses DefaultPriority
		{State: testState{url: "https://ca2.example.com"}, Priority: 50}, // explicit lower priority
	}
	pool := New[string](entries, testDefaults(time.Minute))

	// Should try default priority (100) first
	result, err := pool.Execute(func(s testState) (string, error) {
		require.Equal(t, "https://ca1.example.com", s.url)
		return "default-priority", nil
	})

	require.NoError(t, err)
	require.Equal(t, "default-priority", result)
}

func TestPool_Execute_Failover(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}, Priority: 100},
		{State: testState{url: "https://ca2.example.com"}, Priority: 50},
	}
	pool := New[string](entries, testDefaults(time.Minute))

	var calls []string
	result, err := pool.Execute(func(s testState) (string, error) {
		calls = append(calls, s.url)
		if s.url == "https://ca1.example.com" {
			return "", &infraError{msg: "connection refused"}
		}
		return "from-backup", nil
	})

	require.NoError(t, err)
	require.Equal(t, "from-backup", result)
	require.Equal(t, []string{"https://ca1.example.com", "https://ca2.example.com"}, calls)
}

func TestPool_Execute_NoFailoverOnAuthError(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}, Priority: 100},
		{State: testState{url: "https://ca2.example.com"}, Priority: 50},
	}
	pool := New[string](entries, testDefaults(time.Minute))

	var calls []string
	_, err := pool.Execute(func(s testState) (string, error) {
		calls = append(calls, s.url)
		return "", &authError{msg: "invalid token"}
	})

	// Should return auth error without trying backup
	require.Error(t, err)
	var authErr *authError
	require.ErrorAs(t, err, &authErr)
	require.Equal(t, []string{"https://ca1.example.com"}, calls)
}

func TestPool_Execute_AllUnavailable(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}, Priority: 100},
		{State: testState{url: "https://ca2.example.com"}, Priority: 50},
	}
	pool := New[string](entries, testDefaults(time.Minute))

	_, err := pool.Execute(func(s testState) (string, error) {
		return "", &infraError{msg: "server error"}
	})

	require.Error(t, err)
	var allUnavail *AllUnavailableError
	require.ErrorAs(t, err, &allUnavail)
}

func TestPool_Execute_RoundRobinWithinTier(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}, Priority: 100},
		{State: testState{url: "https://ca2.example.com"}, Priority: 100},
		{State: testState{url: "https://ca3.example.com"}, Priority: 100},
	}
	pool := New[string](entries, testDefaults(time.Minute))

	var urls []string
	for i := 0; i < 6; i++ {
		_, err := pool.Execute(func(s testState) (string, error) {
			urls = append(urls, s.url)
			return "ok", nil
		})
		require.NoError(t, err)
	}

	// Should round-robin through all 3
	require.Len(t, urls, 6)
	// First 3 should be unique
	first3 := make(map[string]bool)
	for _, u := range urls[:3] {
		first3[u] = true
	}
	require.Len(t, first3, 3)
	// Pattern should repeat
	require.Equal(t, urls[0], urls[3])
	require.Equal(t, urls[1], urls[4])
	require.Equal(t, urls[2], urls[5])
}

func TestPool_Execute_CircuitBreakerRecovery(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}},
	}
	// Very short cooldown for testing
	pool := New[string](entries, testDefaults(50*time.Millisecond))

	// First call fails - trips breaker
	_, err := pool.Execute(func(s testState) (string, error) {
		return "", &infraError{msg: "down"}
	})
	require.Error(t, err)

	// Breaker is open - immediate failure
	require.True(t, pool.AllUnavailable())

	// Wait for cooldown
	time.Sleep(100 * time.Millisecond)

	// Breaker should be half-open, allowing a test request
	result, err := pool.Execute(func(s testState) (string, error) {
		return "recovered", nil
	})
	require.NoError(t, err)
	require.Equal(t, "recovered", result)
}

func TestPool_Execute_EmptyPool(t *testing.T) {
	pool := New[string, testState](nil, testDefaults(time.Minute))

	_, err := pool.Execute(func(s testState) (string, error) {
		return "should not be called", nil
	})

	require.Error(t, err)
	var allUnavail *AllUnavailableError
	require.ErrorAs(t, err, &allUnavail)
}

func TestPool_AllUnavailable(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}},
	}
	pool := New[string](entries, testDefaults(time.Minute))

	require.False(t, pool.AllUnavailable())

	// Trip the breaker
	_, _ = pool.Execute(func(s testState) (string, error) {
		return "", &infraError{msg: "down"}
	})

	require.True(t, pool.AllUnavailable())
}

func TestPool_Len(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}, Priority: 100},
		{State: testState{url: "https://ca2.example.com"}, Priority: 50},
	}
	pool := New[string](entries, testDefaults(time.Minute))

	require.Equal(t, 2, pool.Len())
}

func TestPool_Execute_ConcurrentSafety(t *testing.T) {
	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}, Priority: 100},
		{State: testState{url: "https://ca2.example.com"}, Priority: 100},
	}
	pool := New[int](entries, testDefaults(time.Minute))

	var counter atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pool.Execute(func(s testState) (int, error) {
				counter.Add(1)
				return int(counter.Load()), nil
			})
			require.NoError(t, err)
		}()
	}

	wg.Wait()
	require.Equal(t, int32(100), counter.Load())
}

func TestPool_PerEntrySettings(t *testing.T) {
	// Custom settings for one entry with longer cooldown
	customSettings := &gobreaker.Settings{
		Timeout: time.Hour, // Very long timeout
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5 // Require more failures
		},
		IsSuccessful: func(err error) bool {
			return err == nil
		},
	}

	entries := []Entry[testState]{
		{State: testState{url: "https://ca1.example.com"}},                        // uses defaults
		{State: testState{url: "https://ca2.example.com"}, Settings: customSettings}, // custom settings
	}
	pool := New[string](entries, testDefaults(time.Minute))

	// Both should work
	var calls []string
	for i := 0; i < 2; i++ {
		_, err := pool.Execute(func(s testState) (string, error) {
			calls = append(calls, s.url)
			return "ok", nil
		})
		require.NoError(t, err)
	}

	require.Len(t, calls, 2)
}

func TestPool_Execute_StringState(t *testing.T) {
	// Test with simple string state (common case)
	entries := []Entry[string]{
		{State: "https://ca1.example.com", Priority: 100},
		{State: "https://ca2.example.com", Priority: 50},
	}
	pool := New[string, string](entries, testDefaults(time.Minute))

	result, err := pool.Execute(func(url string) (string, error) {
		return "called: " + url, nil
	})

	require.NoError(t, err)
	require.Equal(t, "called: https://ca1.example.com", result)
}
