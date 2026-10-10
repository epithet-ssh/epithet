package directory

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// Static owns directory facts loaded from YAML at startup. Host and realm
// sections in combined configuration files are accepted but supply no facts.
// Reloading requires constructing a new directory.
type Static struct {
	directoryHash hash.Hash
	users         map[string]*User
	ids           map[string]*User
}

// NewStatic concatenates the user records in paths. IDs are required; duplicate
// IDs or nonempty user names and unknown fields are load errors. An omitted
// active field defaults to true. The caller retains ownership of the files.
func NewStatic(paths []string) (*Static, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one directory file is required")
	}
	s := &Static{directoryHash: sha256.New(), users: map[string]*User{}, ids: map[string]*User{}}
	for _, path := range paths {
		if err := s.loadFile(path); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// The accepted YAML shape retains host sections from combined fact files while
// keeping their interpretation outside directory loading.
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
	PrincipalMode string            `yaml:"principal-mode"`
	Realm         string            `yaml:"realm"`
}

func (s *Static) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading directory: %w", err)
	}
	var doc staticDoc
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil && err != io.EOF {
		return fmt.Errorf("parsing directory %s: %w", path, err)
	}
	usersJSON, _ := json.Marshal(doc.Users)
	s.directoryHash.Write(usersJSON)
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
		s.ids[u.ID] = &User{
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
	return nil
}

// LookupUser implements Directory.
func (s *Static) LookupUser(_ context.Context, id string) (*User, Revision, error) {
	return s.ids[id], Revision(s.DirectoryRevision()), nil
}

func (s *Static) ListUserFacts(_ context.Context) ([]User, Revision, error) {
	users := make([]User, 0, len(s.ids))
	for _, user := range s.ids {
		u := *user
		u.Groups = append([]string{}, user.Groups...)
		slices.Sort(u.Groups)
		users = append(users, u)
	}
	slices.SortFunc(users, func(a, b User) int {
		return cmp.Or(cmp.Compare(a.UserName, b.UserName), cmp.Compare(a.ID, b.ID))
	})
	return users, Revision(s.DirectoryRevision()), nil
}

// DirectoryRevision identifies the user records independently of ignored host
// configuration, preserving the existing static directory snapshot identity.
func (s *Static) DirectoryRevision() string {
	return fmt.Sprintf("sha256:%x", s.directoryHash.Sum(nil))
}
