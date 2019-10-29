package hook_test

import (
	"os"
	"testing"

	"github.com/brianm/epithet/pkg/agent/hook"
	"github.com/stretchr/testify/require"
)

func TestHook_Explore(t *testing.T) {
	os.Remove("/tmp/TestHook_Explore")
	defer os.Remove("/tmp/TestHook_Explore")

	h := hook.New("touch {{path}}")

	err := h.Run(map[string]string{"path": "/tmp/TestHook_Explore"})
	require.NoError(t, err)

	_, err = os.Stat("/tmp/TestHook_Explore")
	require.NoError(t, err)
}

func TestHook_Error(t *testing.T) {
	os.Remove("/tmp/TestHook_Error")

	h := hook.New("rm {{path}}")

	err := h.Run(map[string]string{"path": "/tmp/TestHook_Explore"})
	require.Error(t, err)
}
