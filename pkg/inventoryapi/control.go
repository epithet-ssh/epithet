// Package inventoryapi defines the inventory and directory administration
// control API: the JSON operations an administrator or enrolling host sends to
// the advertised inventory endpoint, and the records it returns.
package inventoryapi

import (
	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/inventory"
)

// ControlRequest is one operation at the complete advertised inventory URL.
// An optional single-use token preapproves enrollment. Admin authentication is
// the OIDC bearer header. Revision binds review/edit to the displayed record.
type ControlRequest struct {
	AuditAfter      directory.AuditSequence `json:"audit-after,omitempty"`
	AuditLimit      int                     `json:"audit-limit,omitempty"`
	Alias           string                  `json:"alias,omitempty"`
	Action          string                  `json:"action"`
	ID              string                  `json:"id,omitempty"`
	Revision        uint64                  `json:"revision,omitempty"`
	Host            *inventory.Proposal     `json:"host,omitempty"`
	Token           string                  `json:"token,omitempty"`
	LifetimeSeconds int64                   `json:"lifetime-seconds,omitempty"`
}
type ControlResponse struct {
	Directory      *directory.BindingSnapshot  `json:"directory,omitempty"`
	DirectoryAudit []directory.AuditEvent      `json:"directory-audit,omitempty"`
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
