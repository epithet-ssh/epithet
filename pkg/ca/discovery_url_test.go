package ca

import (
	"testing"
)

func TestExtractLinkURLs_RelativeURL(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		baseURL    string
		wantRel    string
		wantURL    string
	}{
		{
			name:       "relative path",
			linkHeader: `</d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com/api/v1/policy",
			wantRel:    "discovery",
			wantURL:    "https://policy.example.com/d/abc123",
		},
		{
			name:       "relative path with trailing slash base",
			linkHeader: `</d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com/",
			wantRel:    "discovery",
			wantURL:    "https://policy.example.com/d/abc123",
		},
		{
			name:       "relative path preserves port",
			linkHeader: `</d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com:8443/policy",
			wantRel:    "discovery",
			wantURL:    "https://policy.example.com:8443/d/abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := extractLinkURLs(tt.linkHeader, tt.baseURL)
			got := urls[tt.wantRel]
			if got != tt.wantURL {
				t.Errorf("extractLinkURLs()[%q] = %q, want %q", tt.wantRel, got, tt.wantURL)
			}
		})
	}
}

func TestExtractLinkURLs_AbsoluteURL(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		baseURL    string
		wantRel    string
		wantURL    string
	}{
		{
			name:       "absolute URL passed through",
			linkHeader: `<https://discovery.example.com/d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
			wantRel:    "discovery",
			wantURL:    "https://discovery.example.com/d/abc123",
		},
		{
			name:       "absolute URL different port",
			linkHeader: `<https://discovery.example.com:9000/d/abc123>; rel="discovery"`,
			baseURL:    "https://policy.example.com:8443/policy",
			wantRel:    "discovery",
			wantURL:    "https://discovery.example.com:9000/d/abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := extractLinkURLs(tt.linkHeader, tt.baseURL)
			got := urls[tt.wantRel]
			if got != tt.wantURL {
				t.Errorf("extractLinkURLs()[%q] = %q, want %q", tt.wantRel, got, tt.wantURL)
			}
		})
	}
}

func TestExtractLinkURLs_EmptyAndMalformed(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		baseURL    string
	}{
		{
			name:       "empty link header",
			linkHeader: "",
			baseURL:    "https://policy.example.com/policy",
		},
		{
			name:       "no angle brackets",
			linkHeader: `https://example.com/d/abc; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
		},
		{
			name:       "missing opening bracket",
			linkHeader: `https://example.com/d/abc>; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
		},
		{
			name:       "missing closing bracket",
			linkHeader: `<https://example.com/d/abc; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
		},
		{
			name:       "brackets in wrong order",
			linkHeader: `>https://example.com/d/abc<; rel="discovery"`,
			baseURL:    "https://policy.example.com/policy",
		},
		{
			name:       "invalid base URL",
			linkHeader: `</d/abc123>; rel="discovery"`,
			baseURL:    "://invalid",
		},
		{
			name:       "missing rel",
			linkHeader: `</d/abc123>`,
			baseURL:    "https://policy.example.com/policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := extractLinkURLs(tt.linkHeader, tt.baseURL)
			if len(urls) != 0 {
				t.Errorf("extractLinkURLs() = %v, want empty map", urls)
			}
		})
	}
}

func TestExtractLinkURLs_MultipleLinks(t *testing.T) {
	tests := []struct {
		name       string
		linkHeader string
		baseURL    string
		wantURLs   map[string]string
	}{
		{
			name:       "discovery and bootstrap",
			linkHeader: `</d/current>; rel="discovery", </d/bootstrap>; rel="bootstrap"`,
			baseURL:    "https://policy.example.com/policy",
			wantURLs: map[string]string{
				"discovery": "https://policy.example.com/d/current",
				"bootstrap": "https://policy.example.com/d/bootstrap",
			},
		},
		{
			name:       "absolute URLs",
			linkHeader: `<https://cdn.example.com/d/current>; rel="discovery", <https://cdn.example.com/d/bootstrap>; rel="bootstrap"`,
			baseURL:    "https://policy.example.com/policy",
			wantURLs: map[string]string{
				"discovery": "https://cdn.example.com/d/current",
				"bootstrap": "https://cdn.example.com/d/bootstrap",
			},
		},
		{
			name:       "mixed relative and absolute",
			linkHeader: `</d/current>; rel="discovery", <https://cdn.example.com/d/bootstrap>; rel="bootstrap"`,
			baseURL:    "https://policy.example.com/policy",
			wantURLs: map[string]string{
				"discovery": "https://policy.example.com/d/current",
				"bootstrap": "https://cdn.example.com/d/bootstrap",
			},
		},
		{
			name:       "extra whitespace",
			linkHeader: `  </d/current>; rel="discovery"  ,   </d/bootstrap>; rel="bootstrap"  `,
			baseURL:    "https://policy.example.com/policy",
			wantURLs: map[string]string{
				"discovery": "https://policy.example.com/d/current",
				"bootstrap": "https://policy.example.com/d/bootstrap",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := extractLinkURLs(tt.linkHeader, tt.baseURL)
			for rel, wantURL := range tt.wantURLs {
				got := urls[rel]
				if got != wantURL {
					t.Errorf("extractLinkURLs()[%q] = %q, want %q", rel, got, wantURL)
				}
			}
			// Check no extra keys
			if len(urls) != len(tt.wantURLs) {
				t.Errorf("extractLinkURLs() returned %d URLs, want %d", len(urls), len(tt.wantURLs))
			}
		})
	}
}
