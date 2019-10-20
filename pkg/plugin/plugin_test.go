package plugin_test

import (
	"math/rand"
	"testing"

	"github.com/brianm/epithet/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_BigInput(t *testing.T) {
	in := randStringBytes(8192)
	out, err := plugin.Run([]byte(in), "./plug.sh")
	require.NoError(t, err)

	assert.Contains(t, string(out), in)
	assert.Contains(t, string(out), "meow")
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
