package wire

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/epithet-ssh/epithet/pkg/principal"
)

// Principal tells the CA how the resolved host expects its certificate
// principal to be constructed.
type Principal struct {
	Mode  string `json:"mode"`
	Realm string `json:"realm,omitempty"`
}

// Host is one resolved inventory host: the policy-facing resource plus the
// principal metadata the CA needs and policy never sees.
type Host struct {
	HostResource
	Principal Principal `json:"principal"`
}

// UnmarshalJSON decodes the complete inventory host, including principal
// metadata. Using a plain resource prevents promotion of HostResource's custom
// decoder, which would otherwise consume the enclosing object by itself.
func (h *Host) UnmarshalJSON(data []byte) error {
	type resource HostResource
	var raw struct {
		resource
		Accounts  json.RawMessage `json:"accounts"`
		Principal Principal       `json:"principal"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw.Accounts) == 0 {
		return fmt.Errorf("inventory host accounts field is required")
	}
	if err := json.Unmarshal(raw.Accounts, &raw.resource.Accounts); err != nil {
		return fmt.Errorf("invalid inventory host accounts: %w", err)
	}
	*h = Host{HostResource: HostResource(raw.resource), Principal: raw.Principal}
	return nil
}

// Validate checks the requested host and certificate-principal metadata.
func (h Host) Validate(target string) error {
	if err := h.HostResource.Validate(); err != nil {
		return err
	}
	if !slices.Contains(h.Names, target) {
		return fmt.Errorf("inventory host names do not contain requested target")
	}
	switch h.Principal.Mode {
	case "account-name":
	case "epithet-principal-v1":
		if _, err := principal.ParseRealm(h.Principal.Realm); err != nil {
			return fmt.Errorf("invalid principal realm: %w", err)
		}
	default:
		return fmt.Errorf("unknown principal mode %q", h.Principal.Mode)
	}
	return nil
}
