package inventoryserver

import (
	"context"
	"fmt"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// Resolver combines independently owned directory and host snapshots. Each
// source supplies its revision together with the facts from that snapshot.
type Resolver struct {
	Directory directory.Directory
	Hosts     inventory.Hosts
}

func (s *Resolver) Resolve(ctx context.Context, auth wire.Authentication, host string) (*wire.Resolution, error) {
	u, directoryRevision, err := s.Directory.LookupUser(ctx, auth.ID)
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}
	h, revision, err := s.Hosts.LookupHost(ctx, host)

	if err != nil {
		return nil, fmt.Errorf("looking up host: %w", err)
	}
	r := &wire.Resolution{Version: wire.ResolveVersion, Authentication: auth, Target: host,
		Directory: wire.DirectorySnapshot{Revision: string(directoryRevision)},
		Inventory: wire.HostSnapshot{Revision: revision}}
	if u != nil {
		active := u.Active
		r.Directory.User = &wire.User{
			ID: u.ID, UserName: u.UserName, Active: &active,
			Groups: u.Groups, UserType: u.UserType,
			Department: u.Department, Organization: u.Organization,
		}
	}
	if h != nil {
		r.Inventory.Host = &wire.Host{HostResource: wire.HostResource{Names: h.Policy.Names, Labels: h.Policy.Labels, Accounts: h.Policy.Accounts},
			Principal: wire.Principal{Mode: string(h.PrincipalMode.Effective()), Domain: string(h.Domain)}}
	}
	if err := r.Validate(host); err != nil {
		return nil, err
	}
	return r, nil
}
