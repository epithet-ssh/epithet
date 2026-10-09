package inventory

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"maps"
	"os"
	"slices"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"gopkg.in/yaml.v3"
)

// Static is a file-backed inventory: directory users and hosts loaded
// once at startup. Reload is a process restart, like the policy itself.
//
// Host entries come in two forms. An exact entry (`names:`) is one
// registered host. A pattern entry (`pattern:`) uses the same DNS-label-aware
// hostname patterns as Writ host selectors. Exact entries expose all their names;
// pattern entries adopt the requested name. Principal realms are separate
// issuance metadata and never replace host names. Patterns are the
// escape hatch for fleets of short-lived hosts (VM pools, CI runners) that
// follow a naming pattern but cannot be enumerated in a file.
type Static struct {
	ignoreUsers          bool
	ignoreHosts          bool
	directoryHash        hash.Hash
	inventoryHash        hash.Hash
	users                map[string]*directory.User
	ids                  map[string]*directory.User
	hosts                map[string]*ResolvedHost
	patterns             []patternHost // file order; first match wins
	realms               map[principal.Realm]struct{}
	realmReferences      []realmReference
	realmPolicies        map[principal.Realm]realmPolicy
	defaultPrincipalMode PrincipalMode
}

type patternHost struct {
	pattern       hostpattern.Pattern
	labels        map[string]string
	accounts      []string
	principalMode PrincipalMode
	realm         principal.Realm
}

type realmReference struct {
	realm     principal.Realm
	path      string
	hostIndex int
}

type realmPolicy struct {
	labels    map[string]string
	accounts  []string
	path      string
	hostIndex int
}

// WithoutHosts loads only directory facts, independently of host configuration.
func WithoutHosts() StaticOption {
	return func(opts *staticOptions) error { opts.ignoreHosts = true; return nil }
}

// WithoutUsers loads only host facts; user records cannot become a fallback.
func WithoutUsers() StaticOption {
	return func(opts *staticOptions) error { opts.ignoreUsers = true; return nil }
}

type staticOptions struct {
	ignoreUsers          bool
	ignoreHosts          bool
	defaultPrincipalMode PrincipalMode
}

// StaticOption configures static inventory loading.
type StaticOption func(*staticOptions) error

// WithDefaultPrincipalMode sets the mode inherited by host entries that omit
// principal-mode. The default is AccountNamePrincipals.
func WithDefaultPrincipalMode(mode PrincipalMode) StaticOption {
	return func(opts *staticOptions) error {
		if err := mode.Validate(); err != nil {
			return err
		}
		opts.defaultPrincipalMode = mode.Effective()
		return nil
	}
}

// The file format. Users use RFC 7643 field names (userName, userType,
// enterprise department/organization); hosts mirror writ's host model.
type staticDoc struct {
	Realms []string    `yaml:"realms"`
	Users  []userEntry `yaml:"users"`
	Hosts  []hostEntry `yaml:"hosts"`
}

type userEntry struct {
	UserName     string   `yaml:"userName"`
	ID           string   `yaml:"id"`
	Active       *bool    `yaml:"active"` // default true
	Groups       []string `yaml:"groups"`
	UserType     string   `yaml:"userType"`
	Department   string   `yaml:"department"`
	Organization string   `yaml:"organization"`
}

type hostEntry struct {
	Names         []string          `yaml:"names"`
	Pattern       string            `yaml:"pattern"`
	Labels        map[string]string `yaml:"labels"`
	Accounts      []string          `yaml:"accounts"`
	PrincipalMode PrincipalMode     `yaml:"principal-mode"`
	Realm         string            `yaml:"realm"`
}

// NewStatic loads an inventory from one or more YAML files. Files
// concatenate; a missing id, duplicate id/userName, or duplicate
// exact host name across the set is a load error. All IDs belong to the
// inventory service's single configured provider/tenant. Decoding is strict — an unknown
// field is an error, not a silently ignored typo.
func NewStatic(paths []string, options ...StaticOption) (*Static, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one inventory file is required")
	}
	opts := staticOptions{defaultPrincipalMode: AccountNamePrincipals}
	for _, option := range options {
		if err := option(&opts); err != nil {
			return nil, fmt.Errorf("configuring static inventory: %w", err)
		}
	}
	s := &Static{
		ignoreUsers:   opts.ignoreUsers,
		ignoreHosts:   opts.ignoreHosts,
		directoryHash: sha256.New(), inventoryHash: sha256.New(),
		users:                map[string]*directory.User{},
		ids:                  map[string]*directory.User{},
		hosts:                map[string]*ResolvedHost{},
		realms:               map[principal.Realm]struct{}{},
		realmPolicies:        map[principal.Realm]realmPolicy{},
		defaultPrincipalMode: opts.defaultPrincipalMode,
	}
	s.inventoryHash.Write([]byte(opts.defaultPrincipalMode))
	for _, path := range paths {
		if err := s.loadFile(path); err != nil {
			return nil, err
		}
	}
	if err := s.validateRealmReferences(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Static) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading inventory: %w", err)
	}
	var doc staticDoc
	if err := strictUnmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing inventory %s: %w", path, err)
	}
	if s.ignoreHosts {
		doc.Hosts = nil
		doc.Realms = nil
	}
	if s.ignoreUsers {
		doc.Users = nil
	}
	usersJSON, _ := json.Marshal(doc.Users)
	s.directoryHash.Write(usersJSON)
	hostsJSON, _ := json.Marshal(struct {
		Realms []string
		Hosts  []hostEntry
	}{doc.Realms, doc.Hosts})
	s.inventoryHash.Write(hostsJSON)
	for i, raw := range doc.Realms {
		realm, err := principal.ParseNamedRealm(raw)
		if err != nil {
			return fmt.Errorf("%s: realms[%d]: %w", path, i, err)
		}
		if _, exists := s.realms[realm]; exists {
			return fmt.Errorf("%s: duplicate realm %q", path, realm)
		}
		s.realms[realm] = struct{}{}
	}
	for i, u := range doc.Users {
		if _, ok := s.users[u.UserName]; u.UserName != "" && ok {
			return fmt.Errorf("%s: duplicate user %q", path, u.UserName)
		}
		if u.ID == "" {
			return fmt.Errorf("%s: users[%d] (%q) has no id; use the claim selected by your configured identity mode", path, i, u.UserName)
		}
		if previous, ok := s.ids[u.ID]; ok {
			return fmt.Errorf("%s: duplicate id %q for users %q and %q", path, u.ID, previous.UserName, u.UserName)
		}
		s.ids[u.ID] = &directory.User{
			UserName:     u.UserName,
			ID:           u.ID,
			Active:       u.Active == nil || *u.Active,
			Groups:       u.Groups,
			UserType:     u.UserType,
			Department:   u.Department,
			Organization: u.Organization,
		}
		if u.UserName != "" {
			s.users[u.UserName] = s.ids[u.ID]
		}
	}
	for i, h := range doc.Hosts {
		mode, err := s.resolvePrincipalMode(h.PrincipalMode)
		if err != nil {
			return fmt.Errorf("%s: hosts[%d]: %w", path, i, err)
		}
		realm, err := parseRealm(h.Realm)
		if err != nil {
			return fmt.Errorf("%s: hosts[%d] realm: %w", path, i, err)
		}
		if mode == EpithetPrincipalV1 && realm == "" {
			return fmt.Errorf("%s: hosts[%d] uses %s but has no realm", path, i, EpithetPrincipalV1)
		}
		if realm != "" && !realm.IsGeneratedHost() {
			if mode != EpithetPrincipalV1 {
				return fmt.Errorf("%s: hosts[%d] named realm %q requires %s", path, i, realm, EpithetPrincipalV1)
			}
			s.realmReferences = append(s.realmReferences, realmReference{
				realm: realm, path: path, hostIndex: i,
			})
			if err := s.recordRealmPolicy(realm, h.Labels, h.Accounts, path, i); err != nil {
				return err
			}
		}
		switch {
		case h.Names != nil && h.Pattern != "":
			return fmt.Errorf("%s: hosts[%d] has both names and pattern — pick one", path, i)
		case h.Names != nil:
			names := slices.Clone(h.Names)
			if len(names) == 0 {
				return fmt.Errorf("%s: hosts[%d] names must not be empty", path, i)
			}
			for j, raw := range names {
				names[j] = hostpattern.NormalizeName(raw)
				if names[j] == "" {
					return fmt.Errorf("%s: hosts[%d] has an empty DNS name", path, i)
				}
			}
			slices.Sort(names)
			host := &ResolvedHost{
				Policy:        Host{Names: names, Labels: h.Labels, Accounts: h.Accounts},
				PrincipalMode: mode,
				Realm:         realm,
			}
			for _, name := range names {
				if _, ok := s.hosts[name]; ok {
					return fmt.Errorf("%s: hosts[%d] duplicate host name %q", path, i, name)
				}
				s.hosts[name] = host
			}
		case h.Pattern != "":
			if realm.IsGeneratedHost() {
				return fmt.Errorf("%s: hosts[%d] pattern %q cannot use generated host realm %q", path, i, h.Pattern, realm)
			}
			pattern, err := hostpattern.Parse(hostpattern.NormalizeName(h.Pattern))
			if err != nil {
				return fmt.Errorf("%s: hosts[%d] pattern %q: %w", path, i, h.Pattern, err)
			}
			s.patterns = append(s.patterns, patternHost{
				pattern:       pattern,
				labels:        h.Labels,
				accounts:      h.Accounts,
				principalMode: mode,
				realm:         realm,
			})
		default:
			return fmt.Errorf("%s: hosts[%d] has neither names nor pattern", path, i)
		}
	}
	return nil
}

// LookupUser implements directory.Directory.
func (s *Static) LookupUser(_ context.Context, id string) (*directory.User, directory.Revision, error) {
	return s.ids[id], directory.Revision(s.DirectoryRevision()), nil
}

func (s *Static) ListUserFacts(_ context.Context) ([]directory.User, directory.Revision, error) {
	users := make([]directory.User, 0, len(s.ids))
	for _, user := range s.ids {
		u := *user
		u.Groups = append([]string{}, user.Groups...)
		slices.Sort(u.Groups)
		users = append(users, u)
	}
	slices.SortFunc(users, func(a, b directory.User) int {
		return cmp.Or(cmp.Compare(a.UserName, b.UserName), cmp.Compare(a.ID, b.ID))
	})
	return users, directory.Revision(s.DirectoryRevision()), nil
}

// LookupHost implements Hosts: exact entries first, then pattern
// entries in file order, first match wins.
func (s *Static) LookupHost(_ context.Context, name string) (*ResolvedHost, string, error) {
	if h, ok := s.hosts[name]; ok {
		return h, s.InventoryRevision(), nil
	}
	for _, p := range s.patterns {
		if p.pattern.Match(name) {
			return &ResolvedHost{
				Policy:        Host{Names: []string{name}, Labels: p.labels, Accounts: p.accounts},
				PrincipalMode: p.principalMode,
				Realm:         p.realm,
			}, s.InventoryRevision(), nil
		}
	}
	return nil, s.InventoryRevision(), nil
}

func (s *Static) resolvePrincipalMode(override PrincipalMode) (PrincipalMode, error) {
	if err := override.Validate(); err != nil {
		return "", err
	}
	if override == "" {
		return s.defaultPrincipalMode, nil
	}
	return override, nil
}

func parseRealm(raw string) (principal.Realm, error) {
	if raw == "" {
		return "", nil
	}
	return principal.ParseRealm(raw)
}

func (s *Static) validateRealmReferences() error {
	for _, ref := range s.realmReferences {
		if _, ok := s.realms[ref.realm]; !ok {
			return fmt.Errorf("%s: hosts[%d] references undeclared realm %q", ref.path, ref.hostIndex, ref.realm)
		}
	}
	return nil
}

func (s *Static) recordRealmPolicy(realm principal.Realm, labels map[string]string, accounts []string, path string, hostIndex int) error {
	previous, exists := s.realmPolicies[realm]
	if !exists {
		s.realmPolicies[realm] = realmPolicy{
			labels: maps.Clone(labels), accounts: slices.Clone(accounts), path: path, hostIndex: hostIndex,
		}
		return nil
	}
	if sameAuthorization(previous.labels, previous.accounts, labels, accounts) {
		return nil
	}
	return fmt.Errorf(
		"%s: hosts[%d] realm %q has different authorization attributes from %s: hosts[%d]",
		path, hostIndex, realm, previous.path, previous.hostIndex)
}

// strictUnmarshal decodes with KnownFields so an unknown field is an
// error rather than a silently ignored typo. An empty document is an
// empty inventory.
func strictUnmarshal(data []byte, target any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(target); err != nil && err != io.EOF {
		return err
	}
	return nil
}

func (s *Static) DirectoryRevision() string {
	return fmt.Sprintf("sha256:%x", s.directoryHash.Sum(nil))
}
func (s *Static) InventoryRevision() string {
	return fmt.Sprintf("sha256:%x", s.inventoryHash.Sum(nil))
}
