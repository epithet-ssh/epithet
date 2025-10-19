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
	b, err := New(
		ctx,
		*testLogger(t),
		"/tmp/foooo", // TODO replace with a tempfile location which we cleanup
		authCommand)
	require.NoError(t, err)
	defer b.Close()

	client, err := rpc.Dial("unix", "/tmp/foooo")
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
