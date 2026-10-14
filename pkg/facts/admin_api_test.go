package facts_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/stretchr/testify/require"
)

// Keep the expected control representation explicit, including null versus empty
// account lists and the shared names field for exact and wildcard names.
func TestControlResponseWireShape(t *testing.T) {
	ts := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	resp := facts.ControlResponse{
		DirectoryAudit: &facts.AuditPage[facts.DirectoryAuditEvent]{Events: []facts.DirectoryAuditEvent{{Time: ts, Actor: "admin", Action: "rebind", ID: "g1", Alias: "ops", PreviousID: "g0"}}, Next: "directory-next"},
		Host: &facts.HostRecord{
			ID: "h1", Revision: 3, Status: "active",
			Host:      facts.InventoryInput{Names: []string{"*.example"}, Labels: map[string]string{"k": "v"}, Accounts: []string{}, PrincipalMode: "account-name", Realm: "d"},
			CreatedAt: ts, UpdatedAt: ts,
		},
		Hosts: []facts.HostRecord{{ID: "h2", Revision: 1, Status: "pending", Host: facts.InventoryInput{Names: []string{"c"}, PrincipalMode: "account-name"}, CreatedAt: ts, UpdatedAt: ts}},
		Token: &facts.EnrollmentToken{ID: "t1", ExpiresAt: ts, UsedBy: "h1", Revoked: true},
		Audit: &facts.AuditPage[facts.HostAuditEvent]{Events: []facts.HostAuditEvent{{At: ts, Actor: "admin", Action: "approve", Resource: "h1"}}, Next: "inventory-next"},
		Error: "boom",
	}
	out, err := json.Marshal(resp)
	require.NoError(t, err)
	require.Equal(t, `{`+
		`"directory-audit":{"events":[{"time":"2026-09-18T12:00:00Z","actor":"admin","action":"rebind","id":"g1","alias":"ops","previous-id":"g0"}],"next":"directory-next"},`+
		`"host":{"id":"h1","revision":3,"status":"active","host":{"names":["*.example"],"labels":{"k":"v"},"accounts":[],"principal-mode":"account-name","realm":"d"},"created-at":"2026-09-18T12:00:00Z","updated-at":"2026-09-18T12:00:00Z"},`+
		`"hosts":[{"id":"h2","revision":1,"status":"pending","host":{"names":["c"],"labels":null,"accounts":null,"principal-mode":"account-name"},"created-at":"2026-09-18T12:00:00Z","updated-at":"2026-09-18T12:00:00Z"}],`+
		`"token":{"id":"t1","expires-at":"2026-09-18T12:00:00Z","used-by":"h1","revoked":true},`+
		`"audit":{"events":[{"at":"2026-09-18T12:00:00Z","actor":"admin","action":"approve","resource":"h1"}],"next":"inventory-next"},`+
		`"error":"boom"}`, string(out))
}

func TestControlRequestWireShape(t *testing.T) {
	req := facts.ControlRequest{AuditCursor: "backend-cursor", AuditLimit: 10, Action: "edit", ID: "h1", Revision: 3,
		Host: &facts.InventoryInput{Names: []string{"a"}, Accounts: nil, PrincipalMode: "account-name"}, Token: "tok", LifetimeSeconds: 60}
	out, err := json.Marshal(req)
	require.NoError(t, err)
	require.Equal(t, `{"audit-cursor":"backend-cursor","audit-limit":10,"action":"edit","id":"h1","revision":3,"host":{"names":["a"],"labels":null,"accounts":null,"principal-mode":"account-name"},"token":"tok","lifetime-seconds":60}`, string(out))
}

func TestActorSnapshotWireShape(t *testing.T) {
	snapshot := facts.ActorSnapshot{User: &facts.Actor{
		UserName: "alice", ID: "subject:alice", Active: false, Groups: []string{"ops"},
		UserType: "employee", Department: "engineering", Organization: "example",
	}}
	out, err := json.Marshal(snapshot)
	require.NoError(t, err)
	require.Equal(t, `{"user":{"UserName":"alice","ID":"subject:alice","Active":false,"Groups":["ops"],"UserType":"employee","Department":"engineering","Organization":"example"}}`, string(out))
}
