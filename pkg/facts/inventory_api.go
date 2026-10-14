package facts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

const InventoryRecordsRelation = "https://epithet.dev/rel/inventory-records"
const InventoryTokensRelation = "https://epithet.dev/rel/inventory-tokens"
const InventoryAuditRelation = "https://epithet.dev/rel/inventory-audit"

// InventoryHost uses the fact vocabulary while retaining the managed store's
// string-valued attributes. Accounts must be explicit, including null or [].
type InventoryHost struct {
	Name       []string           `json:"name,omitempty"`
	Attributes map[string]string  `json:"attributes"`
	Accounts   []string           `json:"accounts"`
	Principal  InventoryPrincipal `json:"principal"`
}
type InventoryPrincipal struct {
	Mode  string `json:"mode"`
	Realm string `json:"realm,omitempty"`
}

func (p *InventoryHost) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["accounts"]; !ok {
		return fmt.Errorf("accounts must be explicit")
	}
	type plain InventoryHost
	var v plain
	if err := DecodeInventoryJSON(data, &v); err != nil {
		return err
	}
	*p = InventoryHost(v)
	return nil
}

// InventoryRecord is the GET/PUT document. Version belongs exclusively in ETag
// and If-Match. A nil Host represents an empty enrollment reservation.
type InventoryRecord struct {
	ID        string         `json:"id"`
	Status    string         `json:"status"`
	Host      *InventoryHost `json:"host"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}
type InventoryCreate struct {
	Host  *InventoryHost `json:"host"`
	Token string         `json:"token,omitempty"`
}
type InventoryTokenCreate struct {
	LifetimeSeconds int64 `json:"lifetimeSeconds"`
}
type InventoryToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// DecodeInventoryJSON rejects unknown fields and trailing documents at the wire boundary.
func DecodeInventoryJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("expected one JSON document")
	}
	return nil
}
func InventoryETag(version uint64) string { return `"` + strconv.FormatUint(version, 10) + `"` }

// InventoryVersion accepts a single strong record ETag, never a wildcard or weak
// tag: a mutation must identify the exact version the operator reviewed.
func InventoryVersion(tag string) (uint64, error) {
	if len(tag) < 3 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return 0, fmt.Errorf("a strong record ETag is required")
	}
	n, err := strconv.ParseUint(tag[1:len(tag)-1], 10, 64)
	if err != nil || n == 0 || InventoryETag(n) != tag {
		return 0, fmt.Errorf("invalid record ETag")
	}
	return n, nil
}
