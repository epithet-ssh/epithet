// Package facts owns authenticated communication with directory and inventory
// services, including issuance lookups and signed control requests. Providers
// supply facts without authenticating end users or implementing administration.
// Built-in HTTP services live in the server subpackage; shared database support
// lives in the independent storage subpackage.
package facts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/epithet-ssh/epithet/pkg/wire"
)

// Revision is optional opaque logging metadata, never a concurrency token.
type Revision struct {
	value   string
	present bool
}

// IsZero distinguishes omitted metadata from a provider-supplied empty string.
func (r Revision) IsZero() bool                 { return !r.present }
func (r Revision) String() string               { return r.value }
func (r Revision) MarshalJSON() ([]byte, error) { return json.Marshal(r.value) }

func (r *Revision) UnmarshalJSON(data []byte) error {
	if !utf8.Valid(data) || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("revision must be a string")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if len(value) > 256 || !utf8.ValidString(value) {
		return fmt.Errorf("revision exceeds 256 UTF-8 bytes or is invalid UTF-8")
	}
	*r = Revision{value: value, present: true}
	return nil
}

type User struct {
	ID           string   `json:"id"`
	UserName     string   `json:"userName,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	UserType     string   `json:"userType,omitempty"`
	Department   string   `json:"department,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Revision     Revision `json:"revision,omitzero"`
}

// Host keeps the inventory account and principal validation contract while
// allowing optional revision metadata alongside it.
type Host struct {
	wire.Host
	Revision Revision `json:"revision,omitzero"`
}

func (h *Host) UnmarshalJSON(data []byte) error {
	var host wire.Host
	if err := json.Unmarshal(data, &host); err != nil {
		return err
	}
	var extra struct {
		Revision Revision `json:"revision"`
	}
	if err := json.Unmarshal(data, &extra); err != nil {
		return err
	}
	*h = Host{Host: host, Revision: extra.Revision}
	return nil
}
