package inmemory

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

type memDir struct {
	users     map[string]directory.ManagedUser
	userNames map[string]directory.ManagedUser
	groups    map[string]directory.ManagedGroup
	events    []directory.AuditEvent
	revision  int
}

func (mem *memDir) SupportsVersioning() bool { return true }
func (mem *memDir) SupportsPatchUser() bool  { return false }
func (mem *memDir) SupportsPatchGroup() bool { return false }

func (mem *memDir) CreateUser(ctx context.Context, user directory.ManagedUser, event directory.AuditEvent) (directory.ManagedUser, error) {
	existing, found := mem.users[user.ID]
	if found {
		return existing, directory.ErrConflict
	}
	_, found = mem.groups[user.ID]
	if found {
		return directory.ManagedUser{}, directory.ErrConflict
	}

	_, found = mem.userNames[cases.Fold().String(norm.NFKC.String(user.UserName))]
	if found {
		return existing, directory.ErrConflict
	}

	mem.revision++
	user.Version = strconv.Itoa(mem.revision)
	mem.users[user.ID] = user
	mem.userNames[cases.Fold().String(norm.NFKC.String(user.UserName))] = user
	mem.recordAudit(event)
	return user, nil
}

func (mem *memDir) ReplaceUser(ctx context.Context, user directory.ManagedUser, match string, event directory.AuditEvent) (directory.ManagedUser, error) {
	old, found := mem.users[user.ID]
	if found {
		if "" != match && old.Version != match {
			return user, directory.ErrVersion
		}
		user.Created = old.Created
	}

	mem.revision++
	user.Version = strconv.Itoa(mem.revision)
	mem.users[user.ID] = user
	mem.recordAudit(event)
	return user, nil
}

func (mem *memDir) DeleteUser(ctx context.Context, id, expectedVersion string, when time.Time, event directory.AuditEvent) error {
	existing, found := mem.users[id]
	if !found {
		return facts.ErrNotFound
	}
	if "" != expectedVersion && existing.Version != expectedVersion {
		return directory.ErrVersion
	}
	mem.revision++
	delete(mem.users, id)
	delete(mem.userNames, existing.UserName)
	for _, group := range mem.groups {
		for i := slices.Index(group.MemberIDs, id); i != -1; i = slices.Index(group.MemberIDs, id) {
			group.MemberIDs = slices.Delete(group.MemberIDs, i, i+1)
		}
		group.Modified = when
		group.Version = strconv.Itoa(mem.revision)
		mem.groups[group.ID] = group
	}
	mem.recordAudit(event)
	return nil
}

func (mem *memDir) GetUser(ctx context.Context, s string) (*directory.ManagedUser, error) {
	user, found := mem.users[s]
	if !found {
		return nil, nil
	}
	return &user, nil
}

func (mem *memDir) ListUsers(ctx context.Context, start, count int) ([]directory.ManagedUser, int, error) {
	if start < 1 || count < 0 {
		return nil, 0, directory.ErrInvalid
	}
	rs := make([]directory.ManagedUser, len(mem.users))
	i := 0
	for k := range mem.users {
		rs[i] = mem.users[k]
		i++
	}
	slices.SortFunc(rs, func(a, b directory.ManagedUser) int { return strings.Compare(a.ID, b.ID) })
	lo := min(start-1, len(rs))
	hi := lo + min(count, len(rs)-lo)
	return rs[lo:hi], len(rs), nil
}

func (mem *memDir) CreateGroup(ctx context.Context, group directory.ManagedGroup, event directory.AuditEvent) (directory.ManagedGroup, error) {
	existing, found := mem.groups[group.ID]
	if found {
		return existing, directory.ErrConflict
	}
	_, found = mem.users[group.ID]
	if found {
		return directory.ManagedGroup{}, directory.ErrConflict
	}
	mem.revision++
	group.Version = strconv.Itoa(mem.revision)
	mem.groups[group.ID] = group
	mem.recordAudit(event)
	return group, nil
}

func (mem *memDir) ReplaceGroup(ctx context.Context, group directory.ManagedGroup, expectedVersion string, event directory.AuditEvent) (directory.ManagedGroup, error) {
	mem.revision++
	old, found := mem.groups[group.ID]
	if found {
		if expectedVersion != "" && old.Version != expectedVersion {
			return old, directory.ErrVersion
		}
		group.Created = old.Created
	}
	group.Version = strconv.Itoa(mem.revision)
	mem.groups[group.ID] = group
	mem.recordAudit(event)
	return group, nil
}

func (mem *memDir) DeleteGroup(ctx context.Context, id, match string, event directory.AuditEvent) error {
	mem.revision++
	delete(mem.groups, id)
	mem.recordAudit(event)
	return nil
}

func (mem *memDir) GetGroup(ctx context.Context, s string) (*directory.ManagedGroup, error) {
	group, found := mem.groups[s]
	if !found {
		return nil, nil
	}
	return &group, nil
}

func (mem *memDir) ListGroups(ctx context.Context, start, count int) ([]directory.ManagedGroup, int, error) {
	if start < 1 || count < 0 {
		return nil, 0, directory.ErrInvalid
	}
	rs := make([]directory.ManagedGroup, len(mem.groups))
	i := 0
	for k := range mem.groups {
		rs[i] = mem.groups[k]
		i++
	}
	slices.SortFunc(rs, func(a, b directory.ManagedGroup) int { return strings.Compare(a.ID, b.ID) })
	lo := min(start-1, len(rs))
	hi := lo + min(count, len(rs)-lo)
	return rs[lo:hi], len(rs), nil
}

func (mem *memDir) Audit(ctx context.Context, cursor string, limit int) ([]directory.AuditEvent, string, error) {
	if limit == 0 {
		limit = directory.DefaultAuditLimit
	}
	if limit < 0 || limit > directory.MaxAuditLimit {
		return nil, "", directory.ErrInvalid
	}
	start := 0
	if cursor != "" {
		var err error
		start, err = strconv.Atoi(cursor)
		if err != nil || start < 0 || start > len(mem.events) {
			return nil, "", directory.ErrInvalid
		}
	}
	end := start + min(limit, len(mem.events)-start)
	next := ""
	if end < len(mem.events) {
		next = strconv.Itoa(end)
	}
	return mem.events[start:end], next, nil
}

func (mem *memDir) LookupUser(ctx context.Context, s string) (*directory.User, error) {
	user, found := mem.users[s]
	if !found {
		return nil, nil
	}
	u, err := mem.managedUserToUser(ctx, user)
	if err != nil {
		panic(err)
	}
	return u, nil
}

func (mem *memDir) managedUserToUser(ctx context.Context, managed directory.ManagedUser) (*directory.User, error) {
	groups := make([]directory.Group, 0)
	for _, group := range mem.groups {
		if slices.Contains(group.MemberIDs, managed.ID) {
			groups = append(groups, group.Group())
		}
	}
	u := directory.User{
		ID:           managed.ID,
		UserName:     managed.UserName,
		Active:       managed.Active,
		UserType:     managed.UserType,
		Department:   managed.Department,
		Organization: managed.Organization,
		Groups:       groups,
	}
	return &u, nil
}

func (mem *memDir) recordAudit(event directory.AuditEvent) {
	mem.events = append(mem.events, event)
}
