package wire

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The JSON wire shape is a compatibility contract for third-party policy
// servers; pin it.
func TestPolicyRequestWireShape(t *testing.T) {
	req := PolicyRequest{Token: "tok"}
	out, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, `{"token":"tok","connection":{"localHost":"","remoteHost":"","remoteUser":"","port":0,"proxyJump":"","hash":""}}`, string(out))
}

func TestCertParamsRoundTrip(t *testing.T) {
	p := CertParams{Identity: "a@b.c", Names: []string{"root"}, Expiration: 5 * time.Minute}
	out, err := json.Marshal(p)
	require.NoError(t, err)
	var back CertParams
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, p.Identity, back.Identity)
	require.Equal(t, p.Expiration, back.Expiration)
}
