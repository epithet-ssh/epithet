// Package inventoryapi defines the inventory and directory administration
// control API: the JSON operations an administrator or enrolling host sends to
// the advertised inventory endpoint, and the records it returns. The types here
// are the wire schema only; storage packages convert to and from them at the
// service boundary and never share their persisted shapes.
package inventoryapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// ControlRequest is one operation at the complete advertised inventory URL.
// An optional single-use token preapproves enrollment. Admin authentication is
// the OIDC bearer header. Revision binds review/edit to the displayed record.
type ControlRequest struct {
	AuditAfter      uint64    `json:"audit-after,omitempty"`
	AuditLimit      int       `json:"audit-limit,omitempty"`
	Alias           string    `json:"alias,omitempty"`
	Action          string    `json:"action"`
	ID              string    `json:"id,omitempty"`
	Revision        uint64    `json:"revision,omitempty"`
	Host            *Proposal `json:"host,omitempty"`
	Token           string    `json:"token,omitempty"`
	LifetimeSeconds int64     `json:"lifetime-seconds,omitempty"`
}

// ControlResponse carries the result of one ControlRequest. Only the fields
// relevant to the requested action are set; Error accompanies a non-2xx status.
type ControlResponse struct {
	Directory      *BindingSnapshot      `json:"directory,omitempty"`
	DirectoryAudit []DirectoryAuditEvent `json:"directory-audit,omitempty"`
	Host           *HostRecord           `json:"host,omitempty"`
	Hosts          []HostRecord          `json:"hosts,omitempty"`
	Token          *EnrollmentToken      `json:"token,omitempty"`
	Tokens         []EnrollmentToken     `json:"tokens,omitempty"`
	Audit          []HostAuditEvent      `json:"audit,omitempty"`
	Error          string                `json:"error,omitempty"`
}

// Capabilities distinguishes host enrollment from directory-only administration.
// An unavailable or malformed endpoint is an error, never static fallback.
type Capabilities struct {
	Version      int      `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// Proposal is the entire editable authorization record for one host. Admission
// and ownership are server-owned metadata, never fields a host can approve for
// itself. Accounts nil means unrestricted; an empty list permits no accounts.
type Proposal struct {
	Names         []string          `json:"names"`
	Labels        map[string]string `json:"labels"`
	Accounts      []string          `json:"accounts"`
	PrincipalMode string            `json:"principal-mode"`
	Domain        string            `json:"domain,omitempty"`
}

// UnmarshalJSON requires accounts at the input boundary. Explicit null is
// unrestricted; [] permits none. Accidentally omitting the field must not
// broaden access, so omission is an error rather than a default.
func (p *Proposal) UnmarshalJSON(data []byte) error {
	type plain Proposal
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["accounts"]; !ok {
		return fmt.Errorf("accounts must be explicit")
	}
	var raw plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	*p = Proposal(raw)
	return nil
}

// HostRecord is one inventory host as administrators see it. Source metadata
// is present only for records the server can attribute to a file or pattern.
type HostRecord struct {
	SourceFile    string    `json:"source-file,omitempty"`
	Pattern       string    `json:"pattern,omitempty"`
	ID            string    `json:"id"`
	Revision      uint64    `json:"revision"`
	Status        string    `json:"status"`
	Proposal      Proposal  `json:"host"`
	CreatedAt     time.Time `json:"created-at"`
	UpdatedAt     time.Time `json:"updated-at"`
	Source        string    `json:"source,omitempty"`
	ShadowedNames []string  `json:"shadowed-names,omitempty"`
}

// EnrollmentToken is a single-use preapproval for host enrollment.
type EnrollmentToken struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires-at"`
	UsedBy    string    `json:"used-by,omitempty"`
	Revoked   bool      `json:"revoked"`
}

// HostAuditEvent records one administrative change to host inventory.
type HostAuditEvent struct {
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Resource string    `json:"resource"`
}

// GroupBinding is one provisioned directory group and its policy alias.
type GroupBinding struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Alias       string `json:"alias,omitempty"`
	Status      string `json:"status"`
}

// BindingSnapshot lets administrators bind a review to the exact directory
// revision they inspected. Deleted bindings retain the former group ID.
type BindingSnapshot struct {
	Revision uint64         `json:"revision"`
	Groups   []GroupBinding `json:"groups"`
}

// DirectoryAuditEvent records one directory mutation. Sequence identifies the
// event independently of directory revisions: several events can belong to
// the same mutation, and zero starts a cursor at the beginning.
type DirectoryAuditEvent struct {
	Sequence   uint64    `json:"sequence"`
	Revision   uint64    `json:"revision"`
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	ID         string    `json:"id"`
	Alias      string    `json:"alias,omitempty"`
	PreviousID string    `json:"previous-id,omitempty"`
}
