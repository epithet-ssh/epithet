package inventoryclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestInventoryNeverForwardsCredentialsThroughRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	client, err := New(tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	_, status, err := client.Control(context.Background(), source.URL, "private-oidc-token", inventoryapi.ControlRequest{Action: "list"})
	require.Error(t, err)
	require.Equal(t, 307, status)
	require.False(t, reached)
}
