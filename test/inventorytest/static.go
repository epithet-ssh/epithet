package inventorytest

import (
	"bytes"
	"context"
	"fmt"
	"github.com/epithet-ssh/epithet/pkg/writ/object"
	"io"
	"os"
	"slices"

	"github.com/epithet-ssh/epithet/pkg/facts/directory"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"gopkg.in/yaml.v3"
)

// Static is a combined YAML fact fixture for integration tests: directory users and hosts loaded
// once at startup. Reload is a process restart, like the policy itself.
//
// inventory.Host entries come in two forms. An exact entry (`names:`) is one
// registered host. A pattern entry (`pattern:`) uses the same DNS-label-aware
// hostname patterns as Writ host selectors. Exact entries expose all their names;
// pattern entries adopt the requested name. Principal realms are separate
// issuance metadata and never replace host names. Patterns are the
// escape hatch for fleets of short-lived hosts (VM pools, CI runners) that
// follow a naming pattern but cannot be enumerated in a file.
type Static struct {
	ignoreUsers          bool
	ignoreHosts          bool
	directory            *directory.Static
	hosts                map[string]*inventory.Host
	patterns             []patternHost // file order; first match wins
	realms               map[principal.Realm]struct{}
	realmReferences      []realmReference
	defaultPrincipalMode inventory.PrincipalMode
}

type patternHost struct {
	pattern       hostpattern.Pattern
	labels        map[string]string
	accounts      []string
	principalMode inventory.PrincipalMode
	realm         principal.Realm
}

type realmReference struct {
	realm     principal.Realm
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
	defaultPrincipalMode inventory.PrincipalMode
}

// StaticOption configures static inventory loading.
type StaticOption func(*staticOptions) error

// WithDefaultPrincipalMode sets the mode inherited by host entries that omit
// principal-mode. The default is inventory.AccountNamePrincipals.
func WithDefaultPrincipalMode(mode inventory.PrincipalMode) StaticOption {
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
	Names        []string          `yaml:"name"`
	Attributes   object.Attributes `yaml:"attributes"`
	UserName     string            `yaml:"userName"`
	ID           string            `yaml:"id"`
	Active       *bool             `yaml:"active"` // default true
	Groups       []object.Object   `yaml:"groups"`
	UserType     string            `yaml:"userType"`
	Department   string            `yaml:"department"`
	Organization string            `yaml:"organization"`
}

type hostEntry struct {
	Names         []string                `yaml:"names"`
	Pattern       string                  `yaml:"pattern"`
	Labels        map[string]string       `yaml:"labels"`
	Accounts      []string                `yaml:"accounts"`
	PrincipalMode inventory.PrincipalMode `yaml:"principal-mode"`
	Realm         string                  `yaml:"realm"`
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
	opts := staticOptions{defaultPrincipalMode: inventory.AccountNamePrincipals}
	for _, option := range options {
		if err := option(&opts); err != nil {
			return nil, fmt.Errorf("configuring static inventory: %w", err)
		}
	}
	s := &Static{
		ignoreUsers:          opts.ignoreUsers,
		ignoreHosts:          opts.ignoreHosts,
		hosts:                map[string]*inventory.Host{},
		realms:               map[principal.Realm]struct{}{},
		defaultPrincipalMode: opts.defaultPrincipalMode,
	}
	if !opts.ignoreUsers {
		var err error
		s.directory, err = directory.NewStatic(paths)
		if err != nil {
			return nil, err
		}
	}
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
	for i, h := range doc.Hosts {
		mode, err := s.resolvePrincipalMode(h.PrincipalMode)
		if err != nil {
			return fmt.Errorf("%s: hosts[%d]: %w", path, i, err)
		}
		realm, err := parseRealm(h.Realm)
		if err != nil {
			return fmt.Errorf("%s: hosts[%d] realm: %w", path, i, err)
		}
		if mode == inventory.EpithetPrincipalV1 && realm == "" {
			return fmt.Errorf("%s: hosts[%d] uses %s but has no realm", path, i, inventory.EpithetPrincipalV1)
		}
		if realm != "" && !realm.IsGeneratedHost() {
			if mode != inventory.EpithetPrincipalV1 {
				return fmt.Errorf("%s: hosts[%d] named realm %q requires %s", path, i, realm, inventory.EpithetPrincipalV1)
			}
			s.realmReferences = append(s.realmReferences, realmReference{
				realm: realm, path: path, hostIndex: i,
			})
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
			host := &inventory.Host{
				Names: names, Labels: h.Labels, Accounts: h.Accounts,
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

// LookupUser delegates directory semantics to the production static loader.
func (s *Static) LookupUser(ctx context.Context, id string) (*directory.User, error) {
	if s.directory == nil {
		return nil, nil
	}
	return s.directory.LookupUser(ctx, id)
}

// LookupHost implements Hosts: exact entries first, then pattern
// entries in file order, first match wins.
func (s *Static) LookupHost(_ context.Context, name string) (*inventory.Host, error) {
	if h, ok := s.hosts[name]; ok {
		return h, nil
	}
	for _, p := range s.patterns {
		if p.pattern.Match(name) {
			return &inventory.Host{
				Names: []string{name}, Labels: p.labels, Accounts: p.accounts,
				PrincipalMode: p.principalMode,
				Realm:         p.realm,
			}, nil
		}
	}
	return nil, nil
}

func (s *Static) resolvePrincipalMode(override inventory.PrincipalMode) (inventory.PrincipalMode, error) {
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
