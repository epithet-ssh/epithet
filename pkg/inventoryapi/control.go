package inventoryapi

import (
	"github.com/epithet-ssh/epithet/pkg/directory/scim"
	"github.com/epithet-ssh/epithet/pkg/inventory"
)

const InventoryRelation = "https://epithet.dev/rel/inventory"

// ControlRequest is one operation at the complete advertised inventory URL.
// An optional single-use token preapproves enrollment. Admin authentication is
// the OIDC bearer header. Revision binds review/edit to the displayed record.
type ControlRequest struct {
	Alias           string              `json:"alias,omitempty"`
	Action          string              `json:"action"`
	ID              string              `json:"id,omitempty"`
	Revision        uint64              `json:"revision,omitempty"`
	Host            *inventory.Proposal `json:"host,omitempty"`
	Token           string              `json:"token,omitempty"`
	LifetimeSeconds int64               `json:"lifetime-seconds,omitempty"`
}
type ControlResponse struct {
	Directory      *scim.BindingSnapshot       `json:"directory,omitempty"`
	DirectoryAudit []scim.AuditEvent           `json:"directory-audit,omitempty"`
	Host           *inventory.HostRecord       `json:"host,omitempty"`
	Hosts          []inventory.HostRecord      `json:"hosts,omitempty"`
	Token          *inventory.EnrollmentToken  `json:"token,omitempty"`
	Tokens         []inventory.EnrollmentToken `json:"tokens,omitempty"`
	Audit          []inventory.AuditEvent      `json:"audit,omitempty"`
	Error          string                      `json:"error,omitempty"`
}

// Capabilities distinguishes host enrollment from directory-only administration.
// An unavailable or malformed endpoint is an error, never static fallback.
type Capabilities struct {
	Version      int      `json:"version"`
	Capabilities []string `json:"capabilities"`
}
