package caclient

import (
	"testing"
)

func TestParseCAURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     CAEndpoint
		wantErr  bool
		errMatch string
	}{
		{
			name:  "simple URL with default priority",
			input: "https://ca.example.com/",
			want: CAEndpoint{
				URL:      "https://ca.example.com/",
				Priority: DefaultPriority,
			},
		},
		{
			name:  "URL with explicit priority",
			input: "priority=50:https://backup-ca.example.com/",
			want: CAEndpoint{
				URL:      "https://backup-ca.example.com/",
				Priority: 50,
			},
		},
		{
			name:  "URL with priority 0",
			input: "priority=0:https://lowest-priority.example.com/",
			want: CAEndpoint{
				URL:      "https://lowest-priority.example.com/",
				Priority: 0,
			},
		},
		{
			name:  "URL with high priority",
			input: "priority=1000:https://primary-ca.example.com/",
			want: CAEndpoint{
				URL:      "https://primary-ca.example.com/",
				Priority: 1000,
			},
		},
		{
			name:  "HTTP URL (allowed for testing)",
			input: "http://localhost:8080/",
			want: CAEndpoint{
				URL:      "http://localhost:8080/",
				Priority: DefaultPriority,
			},
		},
		{
			name:  "URL with path",
			input: "https://ca.example.com/api/v1/cert",
			want: CAEndpoint{
				URL:      "https://ca.example.com/api/v1/cert",
				Priority: DefaultPriority,
			},
		},
		{
			name:  "URL with port",
			input: "https://ca.example.com:8443/",
			want: CAEndpoint{
				URL:      "https://ca.example.com:8443/",
				Priority: DefaultPriority,
			},
		},
		{
			name:  "URL with whitespace trimmed",
			input: "  https://ca.example.com/  ",
			want: CAEndpoint{
				URL:      "https://ca.example.com/",
				Priority: DefaultPriority,
			},
		},
		// Error cases
		{
			name:     "empty string",
			input:    "",
			wantErr:  true,
			errMatch: "empty CA URL",
		},
		{
			name:     "whitespace only",
			input:    "   ",
			wantErr:  true,
			errMatch: "empty CA URL",
		},
		{
			name:     "missing colon after priority value",
			input:    "priority=50https://ca.example.com/",
			wantErr:  true,
			errMatch: "invalid priority value",
		},
		{
			name:     "invalid priority value",
			input:    "priority=abc:https://ca.example.com/",
			wantErr:  true,
			errMatch: "invalid priority value",
		},
		{
			name:     "negative priority",
			input:    "priority=-10:https://ca.example.com/",
			wantErr:  true,
			errMatch: "priority must be non-negative",
		},
		{
			name:     "invalid URL scheme",
			input:    "ftp://ca.example.com/",
			wantErr:  true,
			errMatch: "must use http or https",
		},
		{
			name:     "missing host",
			input:    "https:///path",
			wantErr:  true,
			errMatch: "must have a host",
		},
		{
			name:     "not a URL",
			input:    "not-a-url",
			wantErr:  true,
			errMatch: "must use http or https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCAURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCAURL(%q) expected error containing %q, got nil", tt.input, tt.errMatch)
					return
				}
				if tt.errMatch != "" && !contains(err.Error(), tt.errMatch) {
					t.Errorf("ParseCAURL(%q) error = %q, want error containing %q", tt.input, err.Error(), tt.errMatch)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseCAURL(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got.URL != tt.want.URL {
				t.Errorf("ParseCAURL(%q).URL = %q, want %q", tt.input, got.URL, tt.want.URL)
			}
			if got.Priority != tt.want.Priority {
				t.Errorf("ParseCAURL(%q).Priority = %d, want %d", tt.input, got.Priority, tt.want.Priority)
			}
		})
	}
}

func TestParseCAURLs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		want     []CAEndpoint
		wantErr  bool
		errMatch string
	}{
		{
			name:  "single URL",
			input: []string{"https://ca.example.com/"},
			want: []CAEndpoint{
				{URL: "https://ca.example.com/", Priority: DefaultPriority},
			},
		},
		{
			name: "multiple URLs with different priorities",
			input: []string{
				"priority=200:https://primary.example.com/",
				"https://secondary.example.com/",
				"priority=50:https://backup.example.com/",
			},
			want: []CAEndpoint{
				{URL: "https://primary.example.com/", Priority: 200},
				{URL: "https://secondary.example.com/", Priority: DefaultPriority},
				{URL: "https://backup.example.com/", Priority: 50},
			},
		},
		{
			name:     "empty list",
			input:    []string{},
			wantErr:  true,
			errMatch: "at least one CA URL is required",
		},
		{
			name:     "nil list",
			input:    nil,
			wantErr:  true,
			errMatch: "at least one CA URL is required",
		},
		{
			name:     "one invalid URL in list",
			input:    []string{"https://good.example.com/", "invalid-url"},
			wantErr:  true,
			errMatch: "must use http or https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCAURLs(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCAURLs(%v) expected error containing %q, got nil", tt.input, tt.errMatch)
					return
				}
				if tt.errMatch != "" && !contains(err.Error(), tt.errMatch) {
					t.Errorf("ParseCAURLs(%v) error = %q, want error containing %q", tt.input, err.Error(), tt.errMatch)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseCAURLs(%v) unexpected error: %v", tt.input, err)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("ParseCAURLs(%v) returned %d endpoints, want %d", tt.input, len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i].URL != tt.want[i].URL {
					t.Errorf("ParseCAURLs(%v)[%d].URL = %q, want %q", tt.input, i, got[i].URL, tt.want[i].URL)
				}
				if got[i].Priority != tt.want[i].Priority {
					t.Errorf("ParseCAURLs(%v)[%d].Priority = %d, want %d", tt.input, i, got[i].Priority, tt.want[i].Priority)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
