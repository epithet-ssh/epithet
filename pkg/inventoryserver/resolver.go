package inventoryserver

import (
	"context"
	"fmt"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
)

// Resolver combines independently owned directory and host snapshots. Each
// source supplies its revision together with the facts from that snapshot.
type Resolver struct {
	Directory directory.Directory
	Hosts     inventory.Hosts
}

func (s *Resolver) Resolve(ctx context.Context, auth facts.Authentication, host string) (*inventoryapi.Resolution, error) {
	u, directoryRevision, err := s.Directory.LookupUser(ctx, auth.ID)
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}
	h, revision, err := s.Hosts.LookupHost(ctx, host)

	if err != nil {
		return nil, fmt.Errorf("looking up host: %w", err)
	}
	r := &inventoryapi.Resolution{Version: inventoryapi.Version, Authentication: auth, Target: host,
		Directory: inventoryapi.DirectorySnapshot{Revision: string(directoryRevision)},
		Inventory: inventoryapi.HostSnapshot{Revision: revision}}
	if u != nil {
		active := u.Active
		r.Directory.User = &facts.User{
			ID: u.ID, UserName: u.UserName, Active: &active,
			Groups: u.Groups, UserType: u.UserType,
			Department: u.Department, Organization: u.Organization,
		}
	}
	if h != nil {
		r.Inventory.Host = &inventoryapi.Host{HostResource: facts.HostResource{Names: h.Policy.Names, Labels: h.Policy.Labels, Accounts: h.Policy.Accounts},
			Principal: inventoryapi.Principal{Mode: string(h.PrincipalMode.Effective()), Domain: string(h.Domain)}}
	}
	if err := r.Validate(host); err != nil {
		return nil, err
	}
	return r, nil
}
