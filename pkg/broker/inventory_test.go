package broker

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryclient"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
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
			client, err := inventoryclient.New(server.URL, tlsconfig.Config{Insecure: true})
			require.NoError(t, err)
			b := &Broker{log: *testLogger(t), auth: &Auth{token: "test-token", expiresAt: time.Now().Add(time.Hour)}, inventoryClient: client, publicCAURL: "https://configured.example/"}
			response := b.InventoryWithUserOutput(t.Context(), inventoryapi.ControlRequest{Action: tc.name}, io.Discard)
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
