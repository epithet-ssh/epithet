package caserver_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestURLStuff(t *testing.T) {
	base, err := url.Parse("https://epithet.io/")
	require.NoError(t, err)

	rel1, err := url.Parse("pubkey")
	require.NoError(t, err)

	abs := base.ResolveReference(rel1)

	assert.Equal(t, "https://epithet.io/pubkey", abs.String())
}
