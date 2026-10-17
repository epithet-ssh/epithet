package facts_test

import (
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestInventoryOpaqueETags(t *testing.T) {
	for _, version := range []string{"", "0", "backend:9/uuid+hash==", `literal\backslash`, "a,b", "雪"} {
		actual, err := facts.InventoryVersion(facts.InventoryETag(version))
		require.NoError(t, err)
		require.Equal(t, version, actual)
	}
	require.Empty(t, facts.InventoryETag(""))
	for _, tag := range []string{`*`, `W/"v1"`, `"v1", "v2"`, `v1`, `""`, `"embedded"quote"`, "\"line\nbreak\"", `"contains space"`} {
		_, err := facts.InventoryVersion(tag)
		require.Error(t, err, tag)
	}
}
