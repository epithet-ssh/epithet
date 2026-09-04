package hostpattern

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{name: "standalone star is universal", pattern: "*", host: "blue.api.controlplane.internal", want: true},
		{name: "star stays in one label", pattern: "v*", host: "v42", want: true},
		{name: "star does not cross a dot", pattern: "v*", host: "v42.home", want: false},
		{name: "embedded star matches one label", pattern: "*.controlplane.internal", host: "api.controlplane.internal", want: true},
		{name: "embedded star does not match two labels", pattern: "*.controlplane.internal", host: "blue.api.controlplane.internal", want: false},
		{name: "doublestar matches zero labels", pattern: "**.controlplane.internal", host: "controlplane.internal", want: true},
		{name: "doublestar matches multiple labels", pattern: "**.controlplane.internal", host: "blue.api.controlplane.internal", want: true},
		{name: "middle doublestar matches zero labels", pattern: "api.**.internal", host: "api.internal", want: true},
		{name: "middle doublestar matches multiple labels", pattern: "api.**.internal", host: "api.blue.prod.internal", want: true},
		{name: "question mark stays in one label", pattern: "host-?.internal", host: "host-1.internal", want: true},
		{name: "question mark does not match a dot", pattern: "host-?.internal", host: "host-.internal", want: false},
		{name: "match is anchored", pattern: "api", host: "api.internal", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, err := Parse(tt.pattern)
			require.NoError(t, err)
			require.Equal(t, tt.want, pattern.Match(tt.host))
		})
	}
}

func TestParseRejectsSyntaxOutsideTheHostnamePatternLanguage(t *testing.T) {
	patterns := []string{
		"",
		"host{,.internal}",
		"host[0-9].internal",
		`host\*.internal`,
		"host/internal",
		"foo**.internal",
		"**foo.internal",
		"foo.***.internal",
		"foo.****.internal",
	}

	for _, raw := range patterns {
		t.Run(raw, func(t *testing.T) {
			_, err := Parse(raw)
			require.Error(t, err)
		})
	}
}

func TestInvalidRawMatchFailsClosed(t *testing.T) {
	require.False(t, Match("{api,db}.internal", "api.internal"))
}
