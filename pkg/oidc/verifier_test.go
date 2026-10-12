package oidc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/epithet-ssh/epithet/test/oidctest"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestServiceDiscoveryRecoversFromTemporaryDNSFailure(t *testing.T) {
	idp := oidctest.New(t)
	config, v, err := PrepareService(ValidatorConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID})
	require.NoError(t, err)
	mapped, err := NewValidator(t.Context(), config)
	require.NoError(t, err)
	require.Same(t, v.verifier, mapped.verifier)
	base := v.verifier.client.Transport
	var attempts atomic.Int32
	v.verifier.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if attempts.Add(1) == 1 {
			return nil, &net.DNSError{Name: "issuer", Err: "server misbehaving", IsTemporary: true}
		}
		return base.RoundTrip(r)
	})
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- v.Run(ctx, logger) }()
	require.ErrorIs(t, v.Ready(), ErrUnavailable)
	start := time.Now()
	_, err = v.Validate(t.Context(), "unverified token")
	require.ErrorIs(t, err, ErrUnavailable)
	require.Less(t, time.Since(start), 100*time.Millisecond)
	require.NoError(t, <-done)
	require.NoError(t, v.Ready())
	require.EqualValues(t, 2, attempts.Load())
	require.Contains(t, logs.String(), "server misbehaving")
	require.Contains(t, logs.String(), "retry_in=")
	require.Contains(t, logs.String(), "OIDC discovery recovered")
	_, err = mapped.Validate(t.Context(), idp.MintIDToken("alice", time.Now().Add(time.Minute)))
	require.NoError(t, err)
}

func TestDiscoveryErrorPolicy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"SERVFAIL", &net.DNSError{IsTemporary: true}, true},
		{"DNS timeout", &net.DNSError{IsTimeout: true}, true},
		{"NXDOMAIN", &net.DNSError{IsNotFound: true}, false},
		{"connection refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"connection reset", syscall.ECONNRESET, true},
		{"timeout", context.DeadlineExceeded, true},
		{"429", &discoveryStatusError{429}, true},
		{"503", &discoveryStatusError{503}, true},
		{"404", &discoveryStatusError{404}, false},
		{"certificate", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, false},
		{"cancelled", context.Canceled, false},
		{"invalid document", errors.New("invalid document"), false},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.retry, retryDiscovery(fmt.Errorf("discovery: %w", tc.err))) })
	}
}

func TestServiceDiscoveryPermanentFailuresDoNotRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, "denied"},
		{"forbidden", 403, "denied"},
		{"not found", 404, "missing"},
		{"malformed", 200, "{"},
		{"wrong issuer", 200, `{"issuer":"https://wrong.example","jwks_uri":"https://wrong.example/keys"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, v, err := PrepareService(ValidatorConfig{Issuer: "https://issuer.example", ClientID: "app"})
			require.NoError(t, err)
			calls := 0
			v.verifier.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			require.Error(t, v.Run(t.Context(), slog.New(slog.DiscardHandler)))
			require.Equal(t, 1, calls)
			require.ErrorIs(t, v.Ready(), ErrUnavailable)
		})
	}
}

func TestServiceDiscoveryCancellation(t *testing.T) {
	for _, duringRequest := range []bool{false, true} {
		t.Run(fmt.Sprint("request=", duringRequest), func(t *testing.T) {
			_, v, err := PrepareService(ValidatorConfig{Issuer: "https://issuer.example", ClientID: "app"})
			require.NoError(t, err)
			attempted := make(chan struct{})
			v.verifier.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				close(attempted)
				if duringRequest {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				return nil, &net.DNSError{IsTemporary: true}
			})
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- v.Run(ctx, slog.New(slog.DiscardHandler)) }()
			<-attempted
			if !duringRequest {
				time.Sleep(50 * time.Millisecond)
			}
			cancel()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("discovery did not stop after cancellation")
			}
		})
	}
}

func TestServiceDiscoveryKeepsRetryingWithCappedJitteredBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, v, err := PrepareService(ValidatorConfig{Issuer: "https://issuer.example", ClientID: "app"})
		require.NoError(t, err)
		var attempts []time.Time
		v.verifier.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts = append(attempts, time.Now())
			return nil, &net.DNSError{IsTemporary: true}
		})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- v.Run(ctx, slog.New(slog.DiscardHandler)) }()
		// Fake time exercises the real retry loop through an hour-long outage.
		time.Sleep(time.Hour)
		synctest.Wait()
		cancel()
		require.ErrorIs(t, <-done, context.Canceled)
		require.Greater(t, len(attempts), 100)
		for i := 1; i < len(attempts); i++ {
			upper := 30 * time.Second
			if i <= 5 {
				upper = time.Second << (i - 1)
			}
			interval := attempts[i].Sub(attempts[i-1])
			require.GreaterOrEqual(t, interval, upper/2)
			require.LessOrEqual(t, interval, upper)
		}
	})
}
