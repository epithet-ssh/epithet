// Package facts defines normalized authentication, user, and host data shared
// by inventory resolution and policy evaluation, without transport metadata.
package facts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
)

// Authentication contains inventory's verified identity and session bound.
// It deliberately contains no bearer credentials or provider-specific claims.
type Authentication struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// User contains the directory attributes used by policy. External directory
// protocols are translated into these facts at the inventory boundary.
type User struct {
	ID           string   `json:"id"`
	UserName     string   `json:"userName"`
	Active       *bool    `json:"active"`
	Groups       []string `json:"groups"`
	UserType     string   `json:"userType,omitempty"`
	Department   string   `json:"department,omitempty"`
	Organization string   `json:"organization,omitempty"`
}
type HostResource struct {
	Names  []string          `json:"names"`
	Labels map[string]string `json:"labels"`
	// Nil means ungrounded; a non-nil slice restricts accounts to its members.
	// An empty slice permits no accounts. JSON decoding rejects omission.
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
	if err := json.Unmarshal(raw.Accounts, &raw.plain.Accounts); err != nil {
		return fmt.Errorf("invalid inventory host accounts: %w", err)
	}
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

// Validate checks identity binding and required user fields. Inactivity is a
// structural denial evaluated by policy, not a malformed fact.
func (u *User) Validate(authenticatedID string) error {
	if u.ID != authenticatedID || u.UserName == "" || u.Active == nil {
		return fmt.Errorf("invalid inventory user")
	}
	for _, group := range u.Groups {
		if group == "" {
			return fmt.Errorf("empty inventory group ID")
		}
	}
	return nil
}

// Validate checks host fields whose omission could broaden authorization.
func (h HostResource) Validate() error {
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
