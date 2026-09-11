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
	req := PolicyRequest{}
	out, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, `{"facts":null,"connection":{"remoteHost":"","remoteUser":"","port":0,"proxyJump":"","hash":""}}`, string(out))
}

func TestPolicyResponseWireShape(t *testing.T) {
	deadline := time.Date(2026, 9, 11, 17, 0, 0, 0, time.UTC)
	p := PolicyResponse{TTL: 5 * time.Minute, Extensions: map[string]string{"permit-pty": ""}, NotAfter: deadline, PolicyID: "sha256:policy"}
	out, err := json.Marshal(p)
	require.NoError(t, err)
	require.JSONEq(t, `{"ttl":300000000000,"extensions":{"permit-pty":""},"notAfter":"2026-09-11T17:00:00Z","policyId":"sha256:policy"}`, string(out))
	var back PolicyResponse
	require.NoError(t, json.Unmarshal(out, &back))
	require.Equal(t, p, back)
	p.NotAfter = time.Time{}
	out, err = json.Marshal(p)
	require.NoError(t, err)
	require.NotContains(t, string(out), "notAfter")
}
