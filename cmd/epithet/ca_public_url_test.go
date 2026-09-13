package main

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestPublicInventoryURLValidation(t *testing.T) {
	for _, value := range []string{"", "inventory", "/manage?route=inventory", "https://inventory.example/manage?route=hosts"} {
		require.NoError(t, validatePublicInventoryURL(value, tlsconfig.Config{}), value)
	}
	for _, tc := range []struct{ value, reason string }{
		{"https://user:password@inventory.example/manage", "embedded credentials"},
		{"inventory#host", "fragment"},
		{"inventory>\r\nInjected: value", "Link header"},
		{"file:///tmp/inventory", "HTTP(S)"},
		{"https:///manage", "HTTP(S)"},
	} {
		require.ErrorContains(t, validatePublicInventoryURL(tc.value, tlsconfig.Config{}), tc.reason)
	}
	require.Error(t, validatePublicInventoryURL("http://inventory.example/manage", tlsconfig.Config{}))
	require.NoError(t, validatePublicInventoryURL("http://inventory.example/manage", tlsconfig.Config{Insecure: true}))
}
