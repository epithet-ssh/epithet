package inventoryapi

import "github.com/epithet-ssh/epithet/pkg/inventory"

const InventoryRelation = "https://epithet.dev/rel/inventory"

// ControlRequest is one operation at the complete advertised inventory URL.
// Enrollment credentials are carried only on enrollment; admin authentication
// is the OIDC bearer header. Revision binds review/edit to the displayed record.
type ControlRequest struct {
	Action          string              `json:"action"`
	ID              string              `json:"id,omitempty"`
	Revision        uint64              `json:"revision,omitempty"`
	Host            *inventory.Proposal `json:"host,omitempty"`
	Credential      string              `json:"credential,omitempty"`
	Token           string              `json:"token,omitempty"`
	LifetimeSeconds int64               `json:"lifetime-seconds,omitempty"`
}
type ControlResponse struct {
	CAURL  string                      `json:"ca-url,omitempty"`
	Host   *inventory.HostRecord       `json:"host,omitempty"`
	Hosts  []inventory.HostRecord      `json:"hosts,omitempty"`
	Token  *inventory.EnrollmentToken  `json:"token,omitempty"`
	Tokens []inventory.EnrollmentToken `json:"tokens,omitempty"`
	Secret string                      `json:"secret,omitempty"`
	Audit  []inventory.AuditEvent      `json:"audit,omitempty"`
	Error  string                      `json:"error,omitempty"`
}
