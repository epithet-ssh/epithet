package caclient

import (
	"errors"
	"testing"
	"time"

	gobreaker "github.com/sony/gobreaker/v2"
)

func TestSelector_Next_SingleEndpoint(t *testing.T) {
	endpoints := []CAEndpoint{
		{URL: "https://ca1.example.com/", Priority: 100},
	}

	s := newSelector(endpoints, time.Minute)

	url, breaker := s.next()
	if url != "https://ca1.example.com/" {
		t.Errorf("next() = %q, want %q", url, "https://ca1.example.com/")
	}
	if breaker == nil {
		t.Error("next() returned nil breaker")
	}
}

func TestSelector_Next_PriorityOrder(t *testing.T) {
	endpoints := []CAEndpoint{
		{URL: "https://backup.example.com/", Priority: 50},
		{URL: "https://primary.example.com/", Priority: 100},
		{URL: "https://lowest.example.com/", Priority: 10},
	}

	s := newSelector(endpoints, time.Minute)

	// Should return highest priority first
	url, _ := s.next()
	if url != "https://primary.example.com/" {
		t.Errorf("first next() = %q, want %q", url, "https://primary.example.com/")
	}

	// Should keep returning same URL (only one at priority 100)
	url, _ = s.next()
	if url != "https://primary.example.com/" {
		t.Errorf("second next() = %q, want %q", url, "https://primary.example.com/")
	}
}

func TestSelector_Next_RoundRobinWithinTier(t *testing.T) {
	endpoints := []CAEndpoint{
		{URL: "https://ca1.example.com/", Priority: 100},
		{URL: "https://ca2.example.com/", Priority: 100},
		{URL: "https://ca3.example.com/", Priority: 100},
	}

	s := newSelector(endpoints, time.Minute)

	// Track which URLs we get
	seen := make(map[string]int)
	for i := 0; i < 6; i++ {
		url, _ := s.next()
		seen[url]++
	}

	// Each URL should be returned exactly twice
	for _, ep := range endpoints {
		if seen[ep.URL] != 2 {
			t.Errorf("URL %q returned %d times, want 2", ep.URL, seen[ep.URL])
		}
	}
}

func TestSelector_Next_CircuitBreakerSkipsOpenCA(t *testing.T) {
	endpoints := []CAEndpoint{
		{URL: "https://ca1.example.com/", Priority: 100},
		{URL: "https://ca2.example.com/", Priority: 100},
	}

	s := newSelector(endpoints, time.Minute)

	// Get first CA and trigger its circuit breaker
	url1, breaker1 := s.next()
	if breaker1 == nil {
		t.Fatal("next() returned nil breaker")
	}

	// Simulate a failure to open the circuit breaker
	_, _ = breaker1.Execute(func() (struct{}, error) {
		return struct{}{}, &CAUnavailableError{Message: "test"}
	})

	// Verify the breaker is now open
	if breaker1.State() != gobreaker.StateOpen {
		t.Errorf("breaker state = %v, want StateOpen", breaker1.State())
	}

	// Next call should return the other CA
	url2, _ := s.next()
	if url2 == url1 {
		t.Errorf("next() returned same URL %q after circuit breaker opened", url2)
	}
}

func TestSelector_Next_FallsToLowerTier(t *testing.T) {
	endpoints := []CAEndpoint{
		{URL: "https://primary.example.com/", Priority: 100},
		{URL: "https://backup.example.com/", Priority: 50},
	}

	s := newSelector(endpoints, time.Minute)

	// Get primary and trip its breaker
	url, breaker := s.next()
	if url != "https://primary.example.com/" {
		t.Fatalf("first next() = %q, want primary", url)
	}

	// Trip the circuit breaker
	_, _ = breaker.Execute(func() (struct{}, error) {
		return struct{}{}, &CAUnavailableError{Message: "test"}
	})

	// Should now return backup
	url, _ = s.next()
	if url != "https://backup.example.com/" {
		t.Errorf("next() after primary failed = %q, want backup", url)
	}
}

func TestSelector_Next_AllUnavailable(t *testing.T) {
	endpoints := []CAEndpoint{
		{URL: "https://ca1.example.com/", Priority: 100},
		{URL: "https://ca2.example.com/", Priority: 50},
	}

	s := newSelector(endpoints, time.Minute)

	// Trip both circuit breakers
	for i := 0; i < 2; i++ {
		_, breaker := s.next()
		if breaker != nil {
			_, _ = breaker.Execute(func() (struct{}, error) {
				return struct{}{}, &CAUnavailableError{Message: "test"}
			})
		}
	}

	// Now both should be unavailable
	url, breaker := s.next()
	if url != "" || breaker != nil {
		t.Errorf("next() when all unavailable = (%q, %v), want (\"\", nil)", url, breaker)
	}

	if !s.allUnavailable() {
		t.Error("allUnavailable() = false, want true")
	}
}

func TestSelector_AllUnavailable_SomeAvailable(t *testing.T) {
	endpoints := []CAEndpoint{
		{URL: "https://ca1.example.com/", Priority: 100},
		{URL: "https://ca2.example.com/", Priority: 100},
	}

	s := newSelector(endpoints, time.Minute)

	if s.allUnavailable() {
		t.Error("allUnavailable() with fresh selector = true, want false")
	}
}

func TestIsSuccessfulForCircuitBreaker(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error is successful",
			err:  nil,
			want: true,
		},
		{
			name: "CAUnavailableError is not successful",
			err:  &CAUnavailableError{Message: "server error"},
			want: false,
		},
		{
			name: "InvalidTokenError is successful (don't trip breaker)",
			err:  &InvalidTokenError{Message: "expired"},
			want: true,
		},
		{
			name: "PolicyDeniedError is successful (don't trip breaker)",
			err:  &PolicyDeniedError{Message: "not allowed"},
			want: true,
		},
		{
			name: "InvalidRequestError is successful (don't trip breaker)",
			err:  &InvalidRequestError{Message: "bad request"},
			want: true,
		},
		{
			name: "wrapped CAUnavailableError is not successful",
			err:  errors.New("wrapped: " + (&CAUnavailableError{Message: "test"}).Error()),
			want: false, // Unknown error, treat as infrastructure failure
		},
		{
			name: "generic error is not successful",
			err:  errors.New("connection refused"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSuccessfulForCircuitBreaker(tt.err)
			if got != tt.want {
				t.Errorf("isSuccessfulForCircuitBreaker(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestGroupByPriority(t *testing.T) {
	tests := []struct {
		name   string
		input  []CAEndpoint
		want   int // number of tiers
		sizes  []int
	}{
		{
			name:  "empty",
			input: []CAEndpoint{},
			want:  0,
		},
		{
			name: "single endpoint",
			input: []CAEndpoint{
				{URL: "https://ca.example.com/", Priority: 100},
			},
			want:  1,
			sizes: []int{1},
		},
		{
			name: "same priority",
			input: []CAEndpoint{
				{URL: "https://ca1.example.com/", Priority: 100},
				{URL: "https://ca2.example.com/", Priority: 100},
				{URL: "https://ca3.example.com/", Priority: 100},
			},
			want:  1,
			sizes: []int{3},
		},
		{
			name: "different priorities (pre-sorted)",
			input: []CAEndpoint{
				{URL: "https://high.example.com/", Priority: 200},
				{URL: "https://medium1.example.com/", Priority: 100},
				{URL: "https://medium2.example.com/", Priority: 100},
				{URL: "https://low.example.com/", Priority: 50},
			},
			want:  3,
			sizes: []int{1, 2, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groupByPriority(tt.input)
			if len(got) != tt.want {
				t.Errorf("groupByPriority() returned %d tiers, want %d", len(got), tt.want)
				return
			}
			for i, size := range tt.sizes {
				if len(got[i]) != size {
					t.Errorf("tier %d has %d endpoints, want %d", i, len(got[i]), size)
				}
			}
		})
	}
}
