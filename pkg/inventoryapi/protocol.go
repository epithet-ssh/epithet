// Package inventoryapi defines the v1 resolver protocol independently of Writ
// and storage implementations. CA projects policy inputs from validated results.
package inventoryapi

import (
	"encoding/json"
	"fmt"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/principal"
)

type ResolveRequest struct {
	Token string `json:"token"`
	Host  string `json:"host"`
}
type Principal struct {
	Mode   string `json:"mode"`
	Domain string `json:"domain,omitempty"`
}
type Host struct {
	Resource  facts.HostResource `json:"resource"`
	Principal Principal          `json:"principal"`
}
type DirectorySnapshot struct {
	Revision string      `json:"revision"`
	User     *facts.User `json:"user"`
}
type HostSnapshot struct {
	Revision string `json:"revision"`
	Host     *Host  `json:"host"`
}
type Resolution struct {
	Version        int                  `json:"version"`
	Authentication facts.Authentication `json:"authentication"`
	Host           string               `json:"host"`
	Directory      DirectorySnapshot    `json:"directory"`
	Inventory      HostSnapshot         `json:"inventory"`
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
	if err := r.Authentication.Validate(); err != nil {
		return err
	}
	if r.Directory.Revision == "" || r.Inventory.Revision == "" {
		return fmt.Errorf("inventory snapshot metadata is required")
	}
	if u := r.Directory.User; u != nil {
		if err := u.Validate(r.Authentication.ID); err != nil {
			return err
		}
	}
	if h := r.Inventory.Host; h != nil {
		if err := h.Resource.Validate(); err != nil {
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
