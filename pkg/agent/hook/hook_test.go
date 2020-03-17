package hook_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/agent/hook"
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

func TestHook_State(t *testing.T) {
	os.Remove("/tmp/TestHook_State")
	h := hook.New("wc -c | tee /tmp/TestHook_State")

	// run the hook, passing empty array in as stdin, so 0 len
	err := h.Run(map[string]string{})
	require.NoError(t, err)
	body, err := ioutil.ReadFile("/tmp/TestHook_State")
	require.NoError(t, err)
	// except 0 len recorded
	require.Equal(t, "       0\n", string(body))

	// state should now be "       0\n" so len should be 9
	err = h.Run(map[string]string{})
	require.NoError(t, err)
	body, err = ioutil.ReadFile("/tmp/TestHook_State")
	require.NoError(t, err)
	// expect len 9 for the state, now that it exists :-)
	require.Equal(t, "       9\n", string(body))
}
