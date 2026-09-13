package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

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
// pattern entries adopt the requested name. Destination-bound named domains
// expose that domain as the Writ resource so policy cannot claim per-member
// isolation. Patterns are the
// escape hatch for fleets of short-lived hosts (VM pools, CI runners) that
// follow a naming pattern but cannot be enumerated in a file.
type Static struct {
	sourceFiles          map[*ResolvedHost]string
	directoryHash        hash.Hash
	inventoryHash        hash.Hash
	users                map[string]*directory.User
	ids                  map[string]*directory.User
	hosts                map[string]*ResolvedHost
	patterns             []patternHost // file order; first match wins
	domains              map[principal.Domain]struct{}
	domainReferences     []domainReference
	domainPolicies       map[principal.Domain]domainPolicy
	defaultPrincipalMode PrincipalMode
}

type patternHost struct {
	sourceFile    string
	rawPattern    string
	pattern       hostpattern.Pattern
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
	Domain        string            `yaml:"domain"`
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
		sourceFiles:   map[*ResolvedHost]string{},
		directoryHash: sha256.New(), inventoryHash: sha256.New(),
		users:                map[string]*directory.User{},
		ids:                  map[string]*directory.User{},
		hosts:                map[string]*ResolvedHost{},
		domains:              map[principal.Domain]struct{}{},
		domainPolicies:       map[principal.Domain]domainPolicy{},
		defaultPrincipalMode: opts.defaultPrincipalMode,
	}
	s.inventoryHash.Write([]byte(opts.defaultPrincipalMode))
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
	usersJSON, _ := json.Marshal(doc.Users)
	s.directoryHash.Write(usersJSON)
	hostsJSON, _ := json.Marshal(struct {
		Domains []string
		Hosts   []hostEntry
	}{doc.Domains, doc.Hosts})
	s.inventoryHash.Write(hostsJSON)
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
		if u.ID == "" {
			return fmt.Errorf("%s: users[%d] (%q) has no id; use the claim selected by your configured identity mode", path, i, u.UserName)
		}
		if previous, ok := s.ids[u.ID]; ok {
			return fmt.Errorf("%s: duplicate id %q for users %q and %q", path, u.ID, previous.UserName, u.UserName)
		}
		s.users[u.UserName] = &directory.User{
			UserName:     u.UserName,
			ID:           u.ID,
			Active:       u.Active == nil || *u.Active,
			Groups:       u.Groups,
			UserType:     u.UserType,
			Department:   u.Department,
			Organization: u.Organization,
		}
		s.ids[u.ID] = s.users[u.UserName]
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
				Policy:        resolvedPolicyHost(names, domain, h.Labels, h.Accounts),
				PrincipalMode: mode,
				Domain:        domain,
			}
			s.sourceFiles[host] = path
			for _, name := range names {
				if _, ok := s.hosts[name]; ok {
					return fmt.Errorf("%s: hosts[%d] duplicate host name %q", path, i, name)
				}
				s.hosts[name] = host
			}
		case h.Pattern != "":
			if domain.IsGeneratedHost() {
				return fmt.Errorf("%s: hosts[%d] pattern %q cannot use generated host domain %q", path, i, h.Pattern, domain)
			}
			pattern, err := hostpattern.Parse(hostpattern.NormalizeName(h.Pattern))
			if err != nil {
				return fmt.Errorf("%s: hosts[%d] pattern %q: %w", path, i, h.Pattern, err)
			}
			s.patterns = append(s.patterns, patternHost{
				sourceFile: path, rawPattern: h.Pattern,
				pattern:       pattern,
				labels:        h.Labels,
				accounts:      h.Accounts,
				principalMode: mode,
				domain:        domain,
			})
		default:
			return fmt.Errorf("%s: hosts[%d] has neither names nor pattern", path, i)
		}
	}
	return nil
}

// LookupUser implements directory.Directory.
func (s *Static) LookupUser(_ context.Context, id string) (*directory.User, error) {
	return s.ids[id], nil
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
				Policy:        resolvedPolicyHost([]string{name}, p.domain, p.labels, p.accounts),
				PrincipalMode: p.principalMode,
				Domain:        p.domain,
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
	if !exists {
		s.domainPolicies[domain] = domainPolicy{
			labels: maps.Clone(labels), accounts: slices.Clone(accounts), path: path, hostIndex: hostIndex,
		}
		return nil
	}
	if previous.matches(labels, accounts) {
		return nil
	}
	return fmt.Errorf(
		"%s: hosts[%d] domain %q has different authorization attributes from %s: hosts[%d]",
		path, hostIndex, domain, previous.path, previous.hostIndex)
}

// matches compares the authorization attributes shared by all domain members.
// Account order is irrelevant; unrestricted (nil) differs from no accounts ([]).
func (p domainPolicy) matches(labels map[string]string, accounts []string) bool {
	if !maps.Equal(p.labels, labels) || (p.accounts == nil) != (accounts == nil) {
		return false
	}
	previous, proposed := slices.Clone(p.accounts), slices.Clone(accounts)
	slices.Sort(previous)
	slices.Sort(proposed)
	return slices.Equal(previous, proposed)
}

func resolvedPolicyHost(names []string, domain principal.Domain, labels map[string]string, accounts []string) Host {
	if domain != "" && !domain.IsGeneratedHost() {
		names = []string{domain.String()}
	}
	return Host{Names: names, Labels: labels, Accounts: accounts}
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

// Records provides read-only source information for inventory administration.
func (s *Static) Records() []HostRecord {
	records := []HostRecord{}
	seen := map[*ResolvedHost]bool{}
	for _, h := range s.hosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		names := []string{}
		for n, other := range s.hosts {
			if other == h {
				names = append(names, n)
			}
		}
		slices.Sort(names)
		records = append(records, HostRecord{SourceFile: s.sourceFiles[h], ID: "static:" + names[0], Status: "approved", Source: "static", Proposal: Proposal{Names: names, Labels: maps.Clone(h.Policy.Labels), Accounts: slices.Clone(h.Policy.Accounts), PrincipalMode: h.PrincipalMode, Domain: string(h.Domain)}})
	}
	for _, p := range s.patterns {
		records = append(records, HostRecord{ID: "static-pattern:" + p.rawPattern, Status: "approved", Source: "static", SourceFile: p.sourceFile, Pattern: p.rawPattern, Proposal: Proposal{Labels: maps.Clone(p.labels), Accounts: slices.Clone(p.accounts), PrincipalMode: p.principalMode, Domain: string(p.domain)}})
	}
	slices.SortFunc(records, func(a, b HostRecord) int { return strings.Compare(a.ID, b.ID) })
	return records
}
