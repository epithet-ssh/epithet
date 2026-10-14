package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/test/oidctest"
	"github.com/stretchr/testify/require"
)

func TestInventoryResponseKeepsCAURLLocal(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantURL string
	}{
		{"token", `{"token":{"id":"enrollment-token"},"ca-url":"https://remote.example/"}`, "https://configured.example/"},
		{"hosts", `{"hosts":[],"ca-url":"https://remote.example/"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client, err := facts.NewAdminClient(server.URL, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			session := newAuthSession(func() TokenFunc { return stubTokenFunc })
			defer session.cancel()
			session.auth = &Auth{token: "test-token", expiresAt: time.Now().Add(time.Hour)}
			b := &Broker{log: *testLogger(t), session: session, inventoryClient: client, publicCAURL: "https://configured.example/"}
			response := b.InventoryWithUserOutput(t.Context(), facts.ControlRequest{Action: tc.name}, io.Discard)
			require.Empty(t, response.Error)
			require.Equal(t, tc.wantURL, response.CAURL)

			// The remote API cannot retain or emit the broker-only field.
			remote, err := json.Marshal(response.ControlResponse)
			require.NoError(t, err)
			require.NotContains(t, string(remote), `"ca-url"`)
			// The local protocol still carries enrollment context to the CLI.
			local, err := json.Marshal(Event{Inventory: response})
			require.NoError(t, err)
			var event Event
			require.NoError(t, json.Unmarshal(local, &event))
			require.Equal(t, tc.wantURL, event.Inventory.CAURL)
			require.Equal(t, response.Token, event.Inventory.Token)
		})
	}
}

func TestSCIMPageRefreshesOnlyRejectedAuthentication(t *testing.T) {
	for _, resource := range []string{"Users", "Groups"} {
		t.Run(resource, func(t *testing.T) {
			for _, status := range []int{401, 403} {
				t.Run(fmt.Sprint(status), func(t *testing.T) {
					calls, refreshes := 0, 0
					freshToken := mintValid(t, oidctest.New(t), time.Hour)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						require.Equal(t, "/scim/v2/"+resource, r.URL.Path)
						require.Equal(t, "101", r.URL.Query().Get("startIndex"))
						if calls == 1 {
							require.Equal(t, "Bearer old-token", r.Header.Get("Authorization"))
							w.WriteHeader(status)
							io.WriteString(w, `{"detail":"rejected"}`)
							return
						}
						require.Equal(t, "Bearer "+freshToken, r.Header.Get("Authorization"))
						io.WriteString(w, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"startIndex":101,"itemsPerPage":1,"totalResults":101,"Resources":[{"id":"last"}]}`)
					}))
					defer server.Close()
					client, err := facts.NewAdminClient(server.URL+"/manage", tlsconfig.Config{Insecure: true})
					require.NoError(t, err)
					session := newAuthSession(func() TokenFunc {
						return func(_ context.Context, out io.Writer, force bool) (string, error) {
							require.True(t, force)
							refreshes++
							io.WriteString(out, "refresh progress\n")
							return freshToken, nil
						}
					})
					defer session.cancel()
					session.auth.token = "old-token"
					session.auth.expiresAt = time.Now().Add(time.Hour)
					b := &Broker{log: *testLogger(t), session: session, inventoryClient: client}
					var progress bytes.Buffer
					response := b.listDirectoryWithUserOutput(t.Context(), DirectoryListRequest{Resource: resource, StartIndex: 101}, &progress)
					if status == 401 {
						require.Empty(t, response.Error)
						require.Len(t, response.Page.Resources, 1)
						require.Equal(t, 2, calls)
						require.Equal(t, 1, refreshes)
						require.Equal(t, "refresh progress\n", progress.String())
					} else {
						require.NotEmpty(t, response.Error)
						require.Nil(t, response.Page)
						require.Equal(t, 1, calls)
						require.Zero(t, refreshes)
					}
				})
			}
		})
	}
}
