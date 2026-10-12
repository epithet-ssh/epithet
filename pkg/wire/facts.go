package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
)

// Authentication contains CA's verified identity and session bound.
// It deliberately contains no bearer credentials or provider-specific claims.
type Authentication struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// User is an eligible, identity-bound user returned by a directory provider.
type User = object.User

type HostResource struct {
	ID         string            `json:"id,omitempty"`
	Names      object.Strings    `json:"name"`
	Attributes object.Attributes `json:"attributes,omitempty"`
	// Accounts must be explicit: null is unrestricted and [] permits none.
	Accounts []string `json:"accounts"`
}

// UnmarshalJSON requires an explicit account restriction and decodes it before
// exposing host facts. Keep strict decoding for policy requests, whose outer
// decoder cannot enforce unknown-field checks inside a custom unmarshaler.
func (h *HostResource) UnmarshalJSON(data []byte) error {
	type plain HostResource
	var raw struct {
		plain
		Accounts json.RawMessage `json:"accounts"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	if len(raw.Accounts) == 0 {
		return fmt.Errorf("inventory host accounts field is required")
	}
	var accounts object.Strings
	if err := json.Unmarshal(raw.Accounts, &accounts); err != nil {
		return fmt.Errorf("invalid inventory host accounts: %w", err)
	}
	raw.plain.Accounts = accounts
	*h = HostResource(raw.plain)
	return nil
}

// Validate checks the verified identity and its absolute lifetime bound.
func (a Authentication) Validate() error {
	if a.ID == "" || !a.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("authentication is missing or expired")
	}
	return nil
}

// Validate checks host fields whose omission could broaden authorization.
func (h HostResource) Validate() error {
	if err := h.Attributes.Validate(); err != nil {
		return err
	}
	if len(h.Names) == 0 {
		return fmt.Errorf("inventory host names are required")
	}
	seen := make(map[string]bool, len(h.Names))
	for _, name := range h.Names {
		if name == "" || name != hostpattern.NormalizeName(name) || seen[name] {
			return fmt.Errorf("invalid or duplicate inventory host name %q", name)
		}
		seen[name] = true
	}
	return nil
}
