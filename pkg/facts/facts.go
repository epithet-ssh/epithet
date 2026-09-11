// Package facts defines normalized authentication, user, and host data shared
// by inventory resolution and policy evaluation, without transport metadata.
package facts

import (
	"encoding/json"
	"fmt"
	"time"
)

const UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const EnterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

// Authentication contains inventory's verified identity and session bound.
// It deliberately contains no bearer credentials or provider-specific claims.
type Authentication struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
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
	return nil
}

// Validate checks host fields whose omission could broaden authorization.
func (h HostResource) Validate() error {
	if h.Name == "" {
		return fmt.Errorf("inventory host name is required")
	}
	_, err := h.AccountList()
	return err
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
