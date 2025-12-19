package ca

import (
	"testing"
)

func TestExtractDiscoveryURL_RelativeURL(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		baseURL    string
		want       string
	}{
		{
			name:       "relative path",
			linkHeader: `</d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com/api/v1/policy",
			want:       "https://policy.example.com/d/abc123",
		},
		{
			name:       "relative path with trailing slash base",
			linkHeader: `</d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com/",
			want:       "https://policy.example.com/d/abc123",
		},
		{
			name:       "relative path preserves port",
			linkHeader: `</d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com:8443/policy",
			want:       "https://policy.example.com:8443/d/abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDiscoveryURL(tt.linkHeader, tt.baseURL)
			if got != tt.want {
				t.Errorf("extractDiscoveryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractDiscoveryURL_AbsoluteURL(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		baseURL    string
		want       string
	}{
		{
			name:       "absolute URL passed through",
			linkHeader: `<https://discovery.example.com/d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
			want:       "https://discovery.example.com/d/abc123",
		},
		{
			name:       "absolute URL different port",
			linkHeader: `<https://discovery.example.com:9000/d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com:8443/policy",
			want:       "https://discovery.example.com:9000/d/abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDiscoveryURL(tt.linkHeader, tt.baseURL)
			if got != tt.want {
				t.Errorf("extractDiscoveryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractDiscoveryURL_EmptyAndMalformed(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		baseURL    string
		want       string
	}{
		{
			name:       "empty link header",
			linkHeader: "",
			baseURL:    "https://policy.example.com/policy",
			want:       "",
		},
		{
			name:       "no angle brackets",
			linkHeader: `https://example.com/d/abc; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
			want:       "",
		},
		{
			name:       "missing opening bracket",
			linkHeader: `https://example.com/d/abc>; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
			want:       "",
		},
		{
			name:       "missing closing bracket",
			linkHeader: `<https://example.com/d/abc; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
			want:       "",
		},
		{
			name:       "brackets in wrong order",
			linkHeader: `>https://example.com/d/abc<; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
			want:       "",
		},
		{
			name:       "invalid base URL",
			linkHeader: `</d/abc123>; rel="discovery"`,
			baseURL:    "://invalid",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDiscoveryURL(tt.linkHeader, tt.baseURL)
			if got != tt.want {
				t.Errorf("extractDiscoveryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
