package caclient

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// DefaultPriority is the priority assigned to CA endpoints without an explicit priority.
// Higher priority values are tried first.
const DefaultPriority = 100

// CAEndpoint represents a CA server URL with its priority for failover.
// Higher priority CAs are tried first; lower priority CAs are used as backups.
type CAEndpoint struct {
	URL      string
	Priority int
}

// ParseCAURL parses a CA URL string into a CAEndpoint.
// Format: "priority=N:https://ca.example.com/" or just "https://ca.example.com/"
// If no priority is specified, DefaultPriority (100) is used.
func ParseCAURL(s string) (CAEndpoint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return CAEndpoint{}, fmt.Errorf("empty CA URL")
	}

	// Check for priority prefix: "priority=N:"
	if strings.HasPrefix(s, "priority=") {
		// Find the colon after the priority value
		colonIdx := strings.Index(s[9:], ":")
		if colonIdx == -1 {
			return CAEndpoint{}, fmt.Errorf("invalid CA URL format: missing colon after priority value in %q", s)
		}
		colonIdx += 9 // Adjust for "priority=" prefix

		priorityStr := s[9:colonIdx]
		priority, err := strconv.Atoi(priorityStr)
		if err != nil {
			return CAEndpoint{}, fmt.Errorf("invalid priority value %q in CA URL: %w", priorityStr, err)
		}
		if priority < 0 {
			return CAEndpoint{}, fmt.Errorf("priority must be non-negative, got %d", priority)
		}

		urlStr := s[colonIdx+1:]
		if err := validateCAURL(urlStr); err != nil {
			return CAEndpoint{}, err
		}

		return CAEndpoint{
			URL:      urlStr,
			Priority: priority,
		}, nil
	}

	// No priority prefix, use default priority
	if err := validateCAURL(s); err != nil {
		return CAEndpoint{}, err
	}

	return CAEndpoint{
		URL:      s,
		Priority: DefaultPriority,
	}, nil
}

// ParseCAURLs parses multiple CA URL strings into CAEndpoints.
// Returns an error if any URL is invalid or if the list is empty.
func ParseCAURLs(urls []string) ([]CAEndpoint, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("at least one CA URL is required")
	}

	endpoints := make([]CAEndpoint, 0, len(urls))
	for _, u := range urls {
		ep, err := ParseCAURL(u)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, ep)
	}

	return endpoints, nil
}

// validateCAURL checks that the URL is a valid HTTP(S) URL.
func validateCAURL(s string) error {
	if s == "" {
		return fmt.Errorf("empty CA URL")
	}

	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid CA URL %q: %w", s, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("CA URL must use http or https scheme, got %q", u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("CA URL must have a host")
	}

	return nil
}
