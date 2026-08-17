package caclient

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindLinkTarget(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
		found  bool
	}{
		{
			name:   "quoted rel",
			values: []string{`<discovery>; rel="https://epithet.dev/rel/auth"`},
			want:   "discovery",
			found:  true,
		},
		{
			name:   "token rel does not match",
			values: []string{`<other>; rel=next`},
			want:   "",
			found:  false,
		},
		{
			name:   "several link-values in one header",
			values: []string{`<a>; rel="next", <discovery>; rel="https://epithet.dev/rel/auth"`},
			want:   "discovery",
			found:  true,
		},
		{
			name: "several Link header lines",
			values: []string{
				`<a>; rel="next"`,
				`<discovery>; rel="https://epithet.dev/rel/auth"`,
			},
			want:  "discovery",
			found: true,
		},
		{
			name:   "rel list, ours not first",
			values: []string{`<discovery>; rel="alternate https://epithet.dev/rel/auth"`},
			want:   "discovery",
			found:  true,
		},
		{
			name:   "comma inside a quoted param is not a separator",
			values: []string{`<discovery>; title="a, b"; rel="https://epithet.dev/rel/auth"`},
			want:   "discovery",
			found:  true,
		},
		{
			name:   "no matching relation",
			values: []string{`<a>; rel="alternate"`},
			want:   "",
			found:  false,
		},
		{
			name:   "malformed value is skipped",
			values: []string{`not-a-link, <discovery>; rel="https://epithet.dev/rel/auth"`},
			want:   "discovery",
			found:  true,
		},
		{
			name:   "no Link header at all",
			values: nil,
			want:   "",
			found:  false,
		},
		{
			name:   "repeated parameter, first occurrence wins",
			values: []string{`<a>; rel="alternate"; rel="https://epithet.dev/rel/auth"`},
			want:   "",
			found:  false,
		},
		{
			name:   "parameter key is case-insensitive",
			values: []string{`<discovery>; REL="https://epithet.dev/rel/auth"`},
			want:   "discovery",
			found:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tt.values {
				h.Add("Link", v)
			}
			got, ok := findLinkTarget(h, relAuth)
			require.Equal(t, tt.found, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestResolveLinkTarget(t *testing.T) {
	tests := []struct {
		name  string
		final string
		ref   string
		want  string
	}{
		{
			name:  "base without trailing slash keeps the prefix",
			final: "https://whee.example.com/epithet/ca",
			ref:   "discovery",
			want:  "https://whee.example.com/epithet/ca/discovery",
		},
		{
			name:  "base with trailing slash resolves identically",
			final: "https://whee.example.com/epithet/ca/",
			ref:   "discovery",
			want:  "https://whee.example.com/epithet/ca/discovery",
		},
		{
			name:  "empty path",
			final: "https://ca.example.com",
			ref:   "discovery",
			want:  "https://ca.example.com/discovery",
		},
		{
			name:  "root path",
			final: "https://ca.example.com/",
			ref:   "discovery",
			want:  "https://ca.example.com/discovery",
		},
		{
			name:  "query on the base does not leak into the result",
			final: "https://ca.example.com/?debug=1",
			ref:   "discovery",
			want:  "https://ca.example.com/discovery",
		},
		{
			name:  "absolute reference wins over the base",
			final: "https://ca.example.com/",
			ref:   "https://elsewhere.example.com/d",
			want:  "https://elsewhere.example.com/d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			final, err := url.Parse(tt.final)
			require.NoError(t, err)

			got, err := resolveLinkTarget(final, tt.ref)
			require.NoError(t, err)
			require.Equal(t, tt.want, got.String())
		})
	}
}

func TestSameOrigin(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "https://ca.example.com/", "https://ca.example.com/discovery", true},
		{"scheme differs", "https://ca.example.com/", "http://ca.example.com/discovery", false},
		{"host differs", "https://ca.example.com/", "https://evil.example.com/discovery", false},
		{"port differs", "https://ca.example.com/", "https://ca.example.com:8443/d", false},
		{"case-insensitive host", "https://CA.example.com/", "https://ca.example.com/d", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := url.Parse(tt.a)
			require.NoError(t, err)
			b, err := url.Parse(tt.b)
			require.NoError(t, err)
			require.Equal(t, tt.want, sameOrigin(a, b))
		})
	}
}
