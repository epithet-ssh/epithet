package inventoryserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
)

// Resolver combines independently owned directory and host snapshots. Static
// data is immutable for the lifetime of this resolver; future dynamic sources
// must supply coherent snapshot reads and explicit freshness semantics.
type Resolver struct {
	Directory         directory.Directory
	Hosts             inventory.Hosts
	DirectoryRevision string
	InventoryRevision string
}

func (s *Resolver) Resolve(ctx context.Context, auth facts.Authentication, host string) (*inventoryapi.Resolution, error) {
	u, err := s.Directory.LookupUser(ctx, auth.ID)
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}
	h, err := s.Hosts.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("looking up host: %w", err)
	}
	r := &inventoryapi.Resolution{Version: inventoryapi.Version, Authentication: auth, Target: host,
		Directory: inventoryapi.DirectorySnapshot{Revision: s.DirectoryRevision},
		Inventory: inventoryapi.HostSnapshot{Revision: s.InventoryRevision}}
	if u != nil {
		active := u.Active
		r.Directory.User = &facts.User{
			ID: u.ID, UserName: u.UserName, Active: &active,
			Groups: u.Groups, UserType: u.UserType,
			Department: u.Department, Organization: u.Organization,
		}
	}
	if h != nil {
		accounts, err := json.Marshal(h.Policy.Accounts)
		if err != nil {
			return nil, err
		}
		r.Inventory.Host = &inventoryapi.Host{HostResource: facts.HostResource{Names: h.Policy.Names, Labels: h.Policy.Labels, Accounts: accounts},
			Principal: inventoryapi.Principal{Mode: string(h.PrincipalMode.Effective()), Domain: string(h.Domain)}}
	}
	if err := r.Validate(host); err != nil {
		return nil, err
	}
	return r, nil
}
