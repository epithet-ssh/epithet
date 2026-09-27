// Package catest supplies controllable evaluators for CA boundary tests.
package catest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// HTTPPolicy lets existing httptest policy fixtures exercise CA validation of
// evaluator results. Production CA evaluation is in-process.
type HTTPPolicy struct {
	URL string
	Key sshcert.RawPrivateKey
	TLS tlsconfig.Config
}

func (p HTTPPolicy) Evaluate(ctx context.Context, conn wire.Connection, facts *wire.PolicyFacts) (*wire.PolicyResponse, error) {
	c, err := serviceauth.NewClient(p.URL, p.Key, serviceauth.Audience, p.TLS)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(Request{Connection: conn, Facts: facts})
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(ctx, "POST", "", nil, data, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(io.LimitReader(resp.Body, wire.MaxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > wire.MaxBodySize {
		return nil, fmt.Errorf("policy response too large")
	}
	if resp.StatusCode != 200 {
		return nil, &wire.PolicyError{StatusCode: resp.StatusCode, Message: string(data)}
	}
	var result wire.PolicyResponse
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Request is the test-only envelope used by controllable evaluator fixtures.
type Request struct {
	Facts      *wire.PolicyFacts `json:"facts"`
	Connection wire.Connection   `json:"connection"`
}
