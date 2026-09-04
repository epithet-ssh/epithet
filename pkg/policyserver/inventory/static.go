package inventory

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/writ/eval"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
	"gopkg.in/yaml.v3"
)

// Static is a file-backed inventory: SCIM-shaped users and hosts loaded
// once at startup. Reload is a process restart, like the policy itself.
//
// Host entries come in two forms. An exact entry (`name:`) is one
// registered host. A pattern entry (`pattern:`, writ glob — `*`/`?`
// only) resolves any requested name it matches. Account-name entries adopt
// the requested name; destination-bound named domains expose that domain as
// the Writ resource so policy cannot claim per-member isolation. Patterns are
// the escape hatch for fleets of short-lived hosts (VM pools, CI runners) that
// follow a naming pattern but cannot be enumerated in a file.
type Static struct {
	users                map[string]*eval.User
	hosts                map[string]*ResolvedHost
	patterns             []patternHost // file order; first match wins
	domains              map[principal.Domain]struct{}
	domainReferences     []domainReference
	domainPolicies       map[principal.Domain]domainPolicy
	defaultPrincipalMode PrincipalMode
}

type patternHost struct {
	pattern       string
	labels        map[string]string
	accounts      []string
	principalMode PrincipalMode
	domain        principal.Domain
}

type domainReference struct {
	domain    principal.Domain
	path      string
	hostIndex int
}

type domainPolicy struct {
	labels    map[string]string
	accounts  []string
	path      string
	hostIndex int
}

type staticOptions struct {
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
	Domains []string    `yaml:"domains"`
	Users   []userEntry `yaml:"users"`
	Hosts   []hostEntry `yaml:"hosts"`
}

type userEntry struct {
	UserName     string   `yaml:"userName"`
	Active       *bool    `yaml:"active"` // default true
	Groups       []string `yaml:"groups"`
	UserType     string   `yaml:"userType"`
	Department   string   `yaml:"department"`
	Organization string   `yaml:"organization"`
}

type hostEntry struct {
	Name          string            `yaml:"name"`
	Pattern       string            `yaml:"pattern"`
	Labels        map[string]string `yaml:"labels"`
	Accounts      []string          `yaml:"accounts"`
	PrincipalMode PrincipalMode     `yaml:"principal-mode"`
	Domain        string            `yaml:"domain"`
}

// NewStatic loads an inventory from one or more YAML files. Files
// concatenate; a duplicate userName or exact host name across the set
// is a load error. Decoding is strict — an unknown field is an error,
// not a silently ignored typo.
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
		users:                map[string]*eval.User{},
		hosts:                map[string]*ResolvedHost{},
		domains:              map[principal.Domain]struct{}{},
		domainPolicies:       map[principal.Domain]domainPolicy{},
		defaultPrincipalMode: opts.defaultPrincipalMode,
	}
	for _, path := range paths {
		if err := s.loadFile(path); err != nil {
			return nil, err
		}
	}
	if err := s.validateDomainReferences(); err != nil {
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
	for i, raw := range doc.Domains {
		domain, err := principal.ParseNamedDomain(raw)
		if err != nil {
			return fmt.Errorf("%s: domains[%d]: %w", path, i, err)
		}
		if _, exists := s.domains[domain]; exists {
			return fmt.Errorf("%s: duplicate domain %q", path, domain)
		}
		s.domains[domain] = struct{}{}
	}
	for i, u := range doc.Users {
		if u.UserName == "" {
			return fmt.Errorf("%s: users[%d] has no userName", path, i)
		}
		if _, ok := s.users[u.UserName]; ok {
			return fmt.Errorf("%s: duplicate user %q", path, u.UserName)
		}
		s.users[u.UserName] = &eval.User{
			ID:     u.UserName,
			Active: u.Active == nil || *u.Active,
			Groups: u.Groups,
			Type:   u.UserType,
			Dept:   u.Department,
			Org:    u.Organization,
		}
	}
	for i, h := range doc.Hosts {
		mode, err := s.resolvePrincipalMode(h.PrincipalMode)
		if err != nil {
			return fmt.Errorf("%s: hosts[%d]: %w", path, i, err)
		}
		domain, err := parseDomain(h.Domain)
		if err != nil {
			return fmt.Errorf("%s: hosts[%d] domain: %w", path, i, err)
		}
		if mode == EpithetPrincipalV1 && domain == "" {
			return fmt.Errorf("%s: hosts[%d] uses %s but has no domain", path, i, EpithetPrincipalV1)
		}
		if domain != "" && !domain.IsGeneratedHost() {
			if mode != EpithetPrincipalV1 {
				return fmt.Errorf("%s: hosts[%d] named domain %q requires %s", path, i, domain, EpithetPrincipalV1)
			}
			s.domainReferences = append(s.domainReferences, domainReference{
				domain: domain, path: path, hostIndex: i,
			})
			if err := s.recordDomainPolicy(domain, h.Labels, h.Accounts, path, i); err != nil {
				return err
			}
		}
		switch {
		case h.Name != "" && h.Pattern != "":
			return fmt.Errorf("%s: hosts[%d] has both name and pattern — pick one", path, i)
		case h.Name != "":
			// Loading is an ingress boundary: names are lowercased here
			// so lookups stay byte compares.
			name := il.HostName(h.Name)
			if _, ok := s.hosts[name]; ok {
				return fmt.Errorf("%s: duplicate host %q", path, name)
			}
			s.hosts[name] = &ResolvedHost{
				Policy:        resolvedPolicyHost(name, domain, h.Labels, h.Accounts),
				PrincipalMode: mode,
				Domain:        domain,
			}
		case h.Pattern != "":
			if domain.IsGeneratedHost() {
				return fmt.Errorf("%s: hosts[%d] pattern %q cannot use generated host domain %q", path, i, h.Pattern, domain)
			}
			s.patterns = append(s.patterns, patternHost{
				pattern:       il.HostName(h.Pattern),
				labels:        h.Labels,
				accounts:      h.Accounts,
				principalMode: mode,
				domain:        domain,
			})
		default:
			return fmt.Errorf("%s: hosts[%d] has neither name nor pattern", path, i)
		}
	}
	return nil
}

// LookupUser implements Inventory.
func (s *Static) LookupUser(_ context.Context, identity string) (*eval.User, error) {
	return s.users[identity], nil
}

// LookupHost implements Inventory: exact entries first, then pattern
// entries in file order, first match wins.
func (s *Static) LookupHost(_ context.Context, name string) (*ResolvedHost, error) {
	if h, ok := s.hosts[name]; ok {
		return h, nil
	}
	for _, p := range s.patterns {
		if eval.GlobMatch(p.pattern, name) {
			return &ResolvedHost{
				Policy:        resolvedPolicyHost(name, p.domain, p.labels, p.accounts),
				PrincipalMode: p.principalMode,
				Domain:        p.domain,
			}, nil
		}
	}
	return nil, nil
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

func parseDomain(raw string) (principal.Domain, error) {
	if raw == "" {
		return "", nil
	}
	return principal.ParseDomain(raw)
}

func (s *Static) validateDomainReferences() error {
	for _, ref := range s.domainReferences {
		if _, ok := s.domains[ref.domain]; !ok {
			return fmt.Errorf("%s: hosts[%d] references undeclared domain %q", ref.path, ref.hostIndex, ref.domain)
		}
	}
	return nil
}

func (s *Static) recordDomainPolicy(domain principal.Domain, labels map[string]string, accounts []string, path string, hostIndex int) error {
	previous, exists := s.domainPolicies[domain]
	canonicalAccounts := slices.Clone(accounts)
	slices.Sort(canonicalAccounts)
	if !exists {
		s.domainPolicies[domain] = domainPolicy{
			labels: maps.Clone(labels), accounts: canonicalAccounts, path: path, hostIndex: hostIndex,
		}
		return nil
	}
	sameAccounts := (previous.accounts == nil) == (accounts == nil) && slices.Equal(previous.accounts, canonicalAccounts)
	if maps.Equal(previous.labels, labels) && sameAccounts {
		return nil
	}
	return fmt.Errorf(
		"%s: hosts[%d] domain %q has different authorization attributes from %s: hosts[%d]",
		path, hostIndex, domain, previous.path, previous.hostIndex)
}

func resolvedPolicyHost(requestedName string, domain principal.Domain, labels map[string]string, accounts []string) eval.Host {
	name := requestedName
	if domain != "" && !domain.IsGeneratedHost() {
		name = domain.String()
	}
	return eval.Host{Name: name, Labels: labels, Accounts: accounts}
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
