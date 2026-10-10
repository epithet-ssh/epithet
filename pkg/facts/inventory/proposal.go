package inventory

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"gopkg.in/yaml.v3"
)

// Proposal is the entire editable authorization record. Admission and ownership
// are server-owned metadata, never fields a host can approve for itself.
type Proposal struct {
	Names         []string          `yaml:"names"`
	Pattern       string            `yaml:"pattern,omitempty"`
	Labels        map[string]string `yaml:"labels"`
	Accounts      []string          `yaml:"accounts"`
	PrincipalMode PrincipalMode     `yaml:"principal-mode"`
	Realm         string            `yaml:"realm,omitempty"`
}

// UnmarshalYAML requires explicit accounts in editor proposals. Accidentally
// deleting accounts must not broaden access.
func (p *Proposal) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("host must be a YAML mapping")
	}
	accounts := false
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "accounts":
			accounts = true
		case "names", "pattern", "labels", "principal-mode", "realm":
		default:
			return fmt.Errorf("unknown host field %q", node.Content[i].Value)
		}
	}
	if !accounts {
		return fmt.Errorf("accounts is required: use [], a list, or explicit null")
	}
	type plainProposal Proposal
	var raw plainProposal
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*p = Proposal(raw)
	return nil
}

// MarshalYAML preserves the distinction between unrestricted accounts (null)
// and an explicit empty account set ([]) in the editor.
func (p Proposal) MarshalYAML() (any, error) {
	type plainProposal Proposal
	var node yaml.Node
	if err := node.Encode(plainProposal(p)); err != nil {
		return nil, err
	}
	if p.Accounts == nil {
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value == "accounts" {
				node.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
				break
			}
		}
	}
	// Show the required realm field in an unfinished destination-bound draft.
	if p.PrincipalMode == EpithetPrincipalV1 && p.Realm == "" {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "realm"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""})
	}
	return &node, nil
}

func (p *Proposal) Validate() error {
	if p.Pattern != "" {
		if len(p.Names) != 0 {
			return fmt.Errorf("provide names or pattern, not both")
		}
		p.Pattern = hostpattern.NormalizeName(p.Pattern)
		if _, err := hostpattern.Parse(p.Pattern); err != nil {
			return err
		}
	} else if len(p.Names) == 0 || len(p.Names) > 64 {
		return fmt.Errorf("provide between 1 and 64 exact DNS names")
	}
	seen := map[string]bool{}
	for i, n := range p.Names {
		n = hostpattern.NormalizeName(n)
		if len(n) == 0 || len(n) > 253 {
			return fmt.Errorf("invalid DNS name %q", n)
		}
		for _, label := range strings.Split(n, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return fmt.Errorf("invalid DNS name %q", n)
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
					return fmt.Errorf("invalid exact DNS name %q", n)
				}
			}
		}
		if seen[n] {
			return fmt.Errorf("duplicate DNS name %q", n)
		}
		seen[n] = true
		p.Names[i] = n
	}
	slices.Sort(p.Names)
	if p.PrincipalMode == "" {
		return fmt.Errorf("principal-mode is required")
	}
	if err := p.PrincipalMode.Validate(); err != nil {
		return err
	}
	if p.Realm != "" {
		d, err := principal.ParseRealm(p.Realm)
		if err != nil {
			return err
		}
		if !d.IsGeneratedHost() && p.PrincipalMode != EpithetPrincipalV1 {
			return fmt.Errorf("named realm %q requires %s", d, EpithetPrincipalV1)
		}
		if d.IsGeneratedHost() && p.Pattern != "" {
			return fmt.Errorf("pattern cannot use generated host realm %q", d)
		}
	}
	if p.PrincipalMode == EpithetPrincipalV1 && p.Realm == "" {
		return fmt.Errorf("realm is required for destination-bound principals")
	}
	seen = map[string]bool{}
	for _, a := range p.Accounts {
		if a == "" || strings.ContainsAny(a, " \t\r\n,:") || strings.IndexFunc(a, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || seen[a] {
			return fmt.Errorf("invalid or duplicate account %q", a)
		}
		seen[a] = true
	}
	return nil
}

// ParseProposal distinguishes an explicit null (ungrounded) account set from
// a missing field, and refuses trailing YAML documents and unknown fields.
func ParseProposal(data []byte) (Proposal, error) {
	var p Proposal
	if err := DecodeYAML(data, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}
func DecodeYAML(data []byte, dst any) error {
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected exactly one YAML document")
	}
	return nil
}
