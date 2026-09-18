package inventoryapi_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/stretchr/testify/require"
)

// The control API is consumed by released CLIs and hosts; field names and
// order are a compatibility contract. A byte comparison catches reordering
// that JSONEq would forgive.
func TestControlResponseWireShape(t *testing.T) {
	ts := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	resp := inventoryapi.ControlResponse{
		Directory:      &inventoryapi.BindingSnapshot{Revision: 7, Groups: []inventoryapi.GroupBinding{{ID: "g1", DisplayName: "Ops", Alias: "ops", Status: "bound"}}},
		DirectoryAudit: []inventoryapi.DirectoryAuditEvent{{Sequence: 1, Revision: 7, Time: ts, Actor: "admin", Action: "rebind", ID: "g1", Alias: "ops", PreviousID: "g0"}},
		Host: &inventoryapi.HostRecord{
			SourceFile: "/f.yaml", Pattern: "*.example", ID: "h1", Revision: 3, Status: "active",
			Proposal:  inventoryapi.Proposal{Names: []string{"a"}, Labels: map[string]string{"k": "v"}, Accounts: []string{}, PrincipalMode: "account-name", Domain: "d"},
			CreatedAt: ts, UpdatedAt: ts, Source: "dynamic", ShadowedNames: []string{"b"},
		},
		Hosts:  []inventoryapi.HostRecord{{ID: "h2", Revision: 1, Status: "pending", Proposal: inventoryapi.Proposal{Names: []string{"c"}, PrincipalMode: "account-name"}, CreatedAt: ts, UpdatedAt: ts}},
		Token:  &inventoryapi.EnrollmentToken{ID: "t1", ExpiresAt: ts, UsedBy: "h1", Revoked: true},
		Tokens: []inventoryapi.EnrollmentToken{{ID: "t2", ExpiresAt: ts}},
		Audit:  []inventoryapi.HostAuditEvent{{At: ts, Actor: "admin", Action: "approve", Resource: "h1"}},
		Error:  "boom",
	}
	out, err := json.Marshal(resp)
	require.NoError(t, err)
	require.Equal(t, `{"directory":{"revision":7,"groups":[{"id":"g1","displayName":"Ops","alias":"ops","status":"bound"}]},`+
		`"directory-audit":[{"sequence":1,"revision":7,"time":"2026-09-18T12:00:00Z","actor":"admin","action":"rebind","id":"g1","alias":"ops","previous-id":"g0"}],`+
		`"host":{"source-file":"/f.yaml","pattern":"*.example","id":"h1","revision":3,"status":"active","host":{"names":["a"],"labels":{"k":"v"},"accounts":[],"principal-mode":"account-name","domain":"d"},"created-at":"2026-09-18T12:00:00Z","updated-at":"2026-09-18T12:00:00Z","source":"dynamic","shadowed-names":["b"]},`+
		`"hosts":[{"id":"h2","revision":1,"status":"pending","host":{"names":["c"],"labels":null,"accounts":null,"principal-mode":"account-name"},"created-at":"2026-09-18T12:00:00Z","updated-at":"2026-09-18T12:00:00Z"}],`+
		`"token":{"id":"t1","expires-at":"2026-09-18T12:00:00Z","used-by":"h1","revoked":true},`+
		`"tokens":[{"id":"t2","expires-at":"2026-09-18T12:00:00Z","revoked":false}],`+
		`"audit":[{"at":"2026-09-18T12:00:00Z","actor":"admin","action":"approve","resource":"h1"}],`+
		`"error":"boom"}`, string(out))
}

func TestControlRequestWireShape(t *testing.T) {
	req := inventoryapi.ControlRequest{AuditAfter: 5, AuditLimit: 10, Alias: "ops", Action: "edit", ID: "h1", Revision: 3,
		Host: &inventoryapi.Proposal{Names: []string{"a"}, Accounts: nil, PrincipalMode: "account-name"}, Token: "tok", LifetimeSeconds: 60}
	out, err := json.Marshal(req)
	require.NoError(t, err)
	require.Equal(t, `{"audit-after":5,"audit-limit":10,"alias":"ops","action":"edit","id":"h1","revision":3,"host":{"names":["a"],"labels":null,"accounts":null,"principal-mode":"account-name"},"token":"tok","lifetime-seconds":60}`, string(out))
}
