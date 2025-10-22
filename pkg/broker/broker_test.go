package broker

import (
	"log/slog"
	"net/rpc"
	"testing"

	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
)

func Test_RpcBasics(t *testing.T) {
	ctx := t.Context()
	authCommand := "echo '6:thello,'"
	socketPath := t.TempDir() + "/broker.sock"
	b, err := New(
		ctx,
		*testLogger(t),
		socketPath,
		authCommand)
	require.NoError(t, err)
	defer b.Close()

	client, err := rpc.Dial("unix", socketPath)
	require.NoError(t, err)

	resp := MatchResponse{}
	err = client.Call("Broker.Match", MatchRequest{}, &resp)
	require.NoError(t, err)

	require.True(t, resp.Allow)
}

func testLogger(t *testing.T) *slog.Logger {
	logger := slog.New(tint.NewHandler(t.Output(), &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "15:04:05",
	}))
	return logger
}
