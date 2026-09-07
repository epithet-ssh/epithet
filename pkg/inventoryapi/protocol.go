// Package inventoryapi defines the v1 resolver protocol independently of Writ
// and storage implementations. The CA carries these facts unchanged to policy.
package inventoryapi

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/epithet-ssh/epithet/pkg/principal"
)

const UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const EnterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

// Authentication contains inventory's verified identity and session bound.
// It deliberately contains no bearer credentials or provider-specific claims.
type Authentication struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type ResolveRequest struct {
	Token string `json:"token"`
	Host  string `json:"host"`
}
type Group struct {
	Value   string `json:"value"`
	Display string `json:"display"`
}
type Enterprise struct {
	Department   string `json:"department,omitempty"`
	Organization string `json:"organization,omitempty"`
}
type User struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id"`
	UserName   string      `json:"userName"`
	Active     *bool       `json:"active"`
	Groups     []Group     `json:"groups"`
	UserType   string      `json:"userType,omitempty"`
	Enterprise *Enterprise `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}
type HostResource struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	// Raw JSON preserves the security-significant distinction between omitted,
	// null (ungrounded), and [] (grounded with no permitted accounts).
	Accounts json.RawMessage `json:"accounts"`
}
type Principal struct {
	Mode   string `json:"mode"`
	Domain string `json:"domain,omitempty"`
}
type Host struct {
	Resource  HostResource `json:"resource"`
	Principal Principal    `json:"principal"`
}
type DirectorySnapshot struct {
	Revision string `json:"revision"`
	User     *User  `json:"user"`
}
type HostSnapshot struct {
	Revision string `json:"revision"`
	Host     *Host  `json:"host"`
}
type Resolution struct {
	Version        int               `json:"version"`
	Authentication Authentication    `json:"authentication"`
	Host           string            `json:"host"`
	ResolvedAt     time.Time         `json:"resolvedAt"`
	Directory      DirectorySnapshot `json:"directory"`
	Inventory      HostSnapshot      `json:"inventory"`
}

// Validate checks both request binding and all fields whose omission could
// broaden authorization. Absence of an entity is represented only by null.
func (r *Resolution) Validate(host string) error {
	if r == nil || r.Version != 1 {
		return fmt.Errorf("inventory resolution version 1 is required")
	}
	if r.Host != host || host == "" || r.Authentication.ID == "" {
		return fmt.Errorf("inventory facts do not match authenticated identity and target")
	}
	if !r.Authentication.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("inventory authentication is missing or expired")
	}
	if r.ResolvedAt.IsZero() || r.Directory.Revision == "" || r.Inventory.Revision == "" {
		return fmt.Errorf("inventory snapshot metadata is required")
	}
	if u := r.Directory.User; u != nil {
		if u.ID != r.Authentication.ID || u.UserName == "" || u.Active == nil {
			return fmt.Errorf("invalid inventory user")
		}
		found := false
		for _, schema := range u.Schemas {
			if schema == UserSchema {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("inventory user schema is required")
		}
		for _, group := range u.Groups {
			if group.Value == "" {
				return fmt.Errorf("empty inventory group ID")
			}
		}
	}
	if h := r.Inventory.Host; h != nil {
		if h.Resource.Name == "" {
			return fmt.Errorf("inventory host name is required")
		}
		if _, err := h.Resource.AccountList(); err != nil {
			return err
		}
		switch h.Principal.Mode {
		case "account-name":
			if h.Resource.Name != host {
				return fmt.Errorf("invalid account-name host binding")
			}
		case "epithet-principal-v1":
			domain, err := principal.ParseDomain(h.Principal.Domain)
			if err != nil {
				return fmt.Errorf("invalid principal domain: %w", err)
			}
			expected := string(domain)
			if domain.IsGeneratedHost() {
				expected = host
			}
			if h.Resource.Name != expected {
				return fmt.Errorf("invalid principal-domain host binding")
			}
		default:
			return fmt.Errorf("unknown principal mode %q", h.Principal.Mode)
		}
	}
	return nil
}

func (h HostResource) AccountList() ([]string, error) {
	if len(h.Accounts) == 0 {
		return nil, fmt.Errorf("inventory host accounts field is required")
	}
	var accounts []string
	if err := json.Unmarshal(h.Accounts, &accounts); err != nil {
		return nil, fmt.Errorf("invalid inventory host accounts: %w", err)
	}
	return accounts, nil
}

func (d *DirectorySnapshot) UnmarshalJSON(data []byte) error {
	type plain DirectorySnapshot
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["user"]; !ok {
		return fmt.Errorf("directory snapshot user field is required")
	}
	return json.Unmarshal(data, (*plain)(d))
}
func (h *HostSnapshot) UnmarshalJSON(data []byte) error {
	type plain HostSnapshot
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["host"]; !ok {
		return fmt.Errorf("inventory snapshot host field is required")
	}
	return json.Unmarshal(data, (*plain)(h))
}
