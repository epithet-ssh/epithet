package facts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
// and If-Match. Every stored record contains host facts.
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

// InventoryETag quotes a backend version without interpreting it. Empty means
// the provider does not expose resource versions, so no header is sent.
func InventoryETag(version string) string {
	if version == "" {
		return ""
	}
	return `"` + version + `"`
}

// InventoryVersion accepts an absent ETag or a single strong opaque ETag.
// Wildcards, weak tags, and lists do not identify a reviewed record version.
func InventoryVersion(tag string) (string, error) {
	if tag == "" {
		return "", nil
	}
	if len(tag) < 3 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return "", fmt.Errorf("a strong record ETag is required")
	}
	version := tag[1 : len(tag)-1]
	for i := 0; i < len(version); i++ {
		c := version[i]
		if c < 0x21 || c == '"' || c == 0x7f {
			return "", fmt.Errorf("invalid record ETag")
		}
	}
	return version, nil
}
