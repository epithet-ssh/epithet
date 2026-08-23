package inventory

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/epithet-ssh/epithet/pkg/writ/eval"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
	"gopkg.in/yaml.v3"
)

// Static is a file-backed inventory: SCIM-shaped users and hosts loaded
// once at startup. Reload is a process restart, like the policy itself.
//
// Host entries come in two forms. An exact entry (`name:`) is one
// registered host. A pattern entry (`pattern:`, writ glob — `*`/`?`
// only) synthesizes a host for any requested name it matches, adopting
// the requested name and carrying the entry's labels: the escape hatch
// for fleets of short-lived hosts (VM pools, CI runners) that follow a
// naming pattern but cannot be enumerated in a file.
type Static struct {
	users    map[string]*eval.User
	hosts    map[string]*eval.Host
	patterns []patternHost // file order; first match wins
}

type patternHost struct {
	pattern  string
	labels   map[string]string
	accounts []string
}

// The file format. Users use RFC 7643 field names (userName, userType,
// enterprise department/organization); hosts mirror writ's host model.
type staticDoc struct {
	Users []userEntry `yaml:"users"`
	Hosts []hostEntry `yaml:"hosts"`
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
	Name     string            `yaml:"name"`
	Pattern  string            `yaml:"pattern"`
	Labels   map[string]string `yaml:"labels"`
	Accounts []string          `yaml:"accounts"`
}

// NewStatic loads an inventory from one or more YAML files. Files
// concatenate; a duplicate userName or exact host name across the set
// is a load error. Decoding is strict — an unknown field is an error,
// not a silently ignored typo.
func NewStatic(paths []string) (*Static, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one inventory file is required")
	}
	s := &Static{
		users: map[string]*eval.User{},
		hosts: map[string]*eval.Host{},
	}
	for _, path := range paths {
		if err := s.loadFile(path); err != nil {
			return nil, err
		}
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
			s.hosts[name] = &eval.Host{Name: name, Labels: h.Labels, Accounts: h.Accounts}
		case h.Pattern != "":
			s.patterns = append(s.patterns, patternHost{
				pattern:  il.HostName(h.Pattern),
				labels:   h.Labels,
				accounts: h.Accounts,
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
func (s *Static) LookupHost(_ context.Context, name string) (*eval.Host, error) {
	if h, ok := s.hosts[name]; ok {
		return h, nil
	}
	for _, p := range s.patterns {
		if eval.GlobMatch(p.pattern, name) {
			return &eval.Host{Name: name, Labels: p.labels, Accounts: p.accounts}, nil
		}
	}
	return nil, nil
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
