package ca_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/epithet-ssh/epithet/pkg/writpolicy"
	"github.com/stretchr/testify/require"
)

func TestMinimalCustomFactsAndOptionalUserName(t *testing.T) {
	idp := oidctest.New(t)
	pub, key, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	userKey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	userVerifier, err := facts.NewVerifierFor(pub, facts.DirectoryAudience)
	require.NoError(t, err)
	hostVerifier, err := facts.NewVerifierFor(pub, facts.InventoryAudience)
	require.NoError(t, err)
	token := idp.MintIDToken("alice", time.Now().Add(time.Hour))
	directory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, userVerifier.Verify(r, nil))
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "/lookup", r.URL.Path)
		require.Equal(t, "subject:alice", r.URL.Query().Get("id"))
		require.NotContains(t, r.Header.Get("Authorization"), token)
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(`{"id":"subject:alice"}`))
	}))
	defer directory.Close()
	inventory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, hostVerifier.Verify(r, nil))
		require.Equal(t, "host", r.URL.Query().Get("host"))
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(`{"names":["host","alias"],"accounts":null,"principal":{"mode":"account-name"}}`))
	}))
	defer inventory.Close()
	for _, tc := range []struct {
		policy  string
		allowed bool
	}{
		{`allow id:"subject:alice" -> root@alias`, true},
		{`allow userName:"subject:alice" -> root@host`, false},
		{`allow userName:"" -> root@host`, false},
		{`allow group:ops -> root@host`, false},
		{`allow * -> root@host`, true},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			policy, diags := writ.Load(tc.policy + "\n")
			require.NotNil(t, policy, "%v", diags)
			eval, _, err := writpolicy.New(policy, nil, writpolicy.Options{})
			require.NoError(t, err)
			var logs bytes.Buffer
			authority, err := ca.New(key, eval, ca.WithLogger(slog.New(slog.NewJSONHandler(&logs, nil))), ca.WithFacts(directory.URL, inventory.URL, oidc.ValidatorConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID, TLSConfig: tlsconfig.Config{Insecure: true}}, wire.AuthConfig{Issuer: idp.Issuer(), ClientID: oidctest.ClientID}, tlsconfig.Config{Insecure: true}))
			require.NoError(t, err)
			result, err := authority.Issue(t.Context(), token, wire.Connection{RemoteHost: "HOST", RemoteUser: "root"}, userKey)
			if tc.allowed {
				require.NoError(t, err)
				require.Empty(t, result.Audit.DirectoryRevision)
				require.Empty(t, result.Audit.InventoryRevision)
				cert, err := sshcert.Parse(result.Certificate)
				require.NoError(t, err)
				require.Equal(t, "subject:alice", cert.KeyId)
			} else {
				require.ErrorIs(t, err, ca.ErrAccessDenied)
			}
			require.NotContains(t, logs.String(), "revision")
		})
	}
}

func TestCertificateAuditOmitsAbsentFactRevisions(t *testing.T) {
	var logs bytes.Buffer
	logger := caserver.NewSlogCertLogger(slog.New(slog.NewJSONHandler(&logs, nil)))
	require.NoError(t, logger.LogCert(t.Context(), &caserver.CertEvent{ID: "id"}))
	var fields map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &fields))
	require.NotContains(t, fields, "directoryRevision")
	require.NotContains(t, fields, "inventoryRevision")
}
