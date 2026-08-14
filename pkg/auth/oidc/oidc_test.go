package oidc

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestAuthenticateCompletesCodeFlowViaAutoApprovingIdP(t *testing.T) {
	idp := oidctest.New(t)
	cfg := Config{IssuerURL: idp.Issuer(), ClientID: oidctest.ClientID}

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The flow prints "To authenticate, visit: <url>"; a goroutine plays the
	// browser by GETting that URL, which the fake IdP auto-approves.
	done := make(chan struct{})
	go func() {
		defer close(done)
		urlRe := regexp.MustCompile(`visit: (\S+)`)
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if m := urlRe.FindSubmatch(out.Bytes()); m != nil {
				resp, err := http.Get(string(m[1]))
				if err == nil {
					resp.Body.Close()
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	idToken, next, err := Authenticate(ctx, cfg, nil, &out)
	<-done
	require.NoError(t, err)
	require.NotEmpty(t, idToken)
	require.NotNil(t, next)
	require.Contains(t, idToken, ".") // it is a JWT
}

func TestAuthenticateReusesValidToken(t *testing.T) {
	idp := oidctest.New(t)
	cfg := Config{IssuerURL: idp.Issuer(), ClientID: oidctest.ClientID}
	prev := &oauth2.Token{AccessToken: "still-good", Expiry: time.Now().Add(time.Hour)}
	prev = prev.WithExtra(map[string]any{"id_token": idp.MintIDToken("x@y.z", time.Now().Add(time.Hour))})

	idToken, _, err := Authenticate(context.Background(), cfg, prev, io.Discard)
	require.NoError(t, err)
	require.NotEmpty(t, idToken)
}
