package broker

import (
	"bytes"
	"strings"
	"testing"

	"github.com/markdingo/netstring"
	"github.com/stretchr/testify/require"
)

func Test_NetStringPlay(t *testing.T) {
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)
	enc.EncodeString('n', "Brian")
	enc.EncodeString('s', "Sailing")
	t.Log(buf.String())
	t.Fail()
}

func Test_NetStringPlay2(t *testing.T) {
	msg := "6:nBrian,8:sSailing,"
	dec := netstring.NewDecoder(strings.NewReader(msg))
	k, m, err := dec.DecodeKeyed()
	require.NoError(t, err)
	require.Equal(t, "n", k.String())
	require.Equal(t, "Brian", string(m))

	k, m, err = dec.DecodeKeyed()
	require.NoError(t, err)
	require.Equal(t, "s", k.String())
	require.Equal(t, "Sailing", string(m))
}

func Test_NetStringPlay3(t *testing.T) {
	msg := "6:nBrian, 8:sSailing,"
	dec := netstring.NewDecoder(strings.NewReader(msg))
	k, m, err := dec.DecodeKeyed()
	require.NoError(t, err)
	require.Equal(t, "n", k.String())
	require.Equal(t, "Brian", string(m))

	k, m, err = dec.DecodeKeyed()
	require.NoError(t, err)
	require.Equal(t, "s", k.String())
	require.Equal(t, "Sailing", string(m))
}
