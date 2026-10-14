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

// UnmarshalYAML reads only editable fields; lifecycle metadata is not an input.
func (p *Host) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected a mapping")
	}
	accounts := false
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "accounts":
			accounts = true
		case "names", "labels", "principal-mode", "realm":
		default:
			return fmt.Errorf("unknown field %q", node.Content[i].Value)
		}
	}
	if !accounts {
		return fmt.Errorf("accounts is required: use [], a list, or explicit null")
	}
	type plain Host
	var raw plain
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*p = Host(raw)
	return nil
}

func (p Host) MarshalYAML() (any, error) {
	type plain Host
	return marshalEditable(plain(p), p.Accounts == nil, p.PrincipalMode == EpithetPrincipalV1 && p.Realm == "")
}

func ParseHost(data []byte) (Host, error) {
	var p Host
	if err := DecodeYAML(data, &p); err != nil {
		return p, err
	}
	err := p.Validate()
	return p, err
}

func marshalEditable(value any, unrestricted, missingRealm bool) (any, error) {
	var node yaml.Node
	if err := node.Encode(value); err != nil {
		return nil, err
	}
	if unrestricted {
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value == "accounts" {
				node.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
			}
		}
	}
	if missingRealm {
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "realm"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""})
	}
	return &node, nil
}

func (p *Host) Validate() error {
	if len(p.Names) == 0 || len(p.Names) > 64 {
		return fmt.Errorf("provide between 1 and 64 names")
	}
	seen := map[string]bool{}
	for i, n := range p.Names {
		n = hostpattern.NormalizeName(n)
		if strings.ContainsAny(n, "*?") {
			if _, err := hostpattern.Parse(n); err != nil {
				return err
			}
		} else {
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
		}
		if seen[n] {
			return fmt.Errorf("duplicate DNS name %q", n)
		}
		seen[n] = true
		p.Names[i] = n
	}
	slices.Sort(p.Names)
	return validateFacts(p.Accounts, p.PrincipalMode, p.Realm)
}

func validateFacts(accounts []string, mode PrincipalMode, realm principal.Realm) error {
	if mode == "" {
		return fmt.Errorf("principal-mode is required")
	}
	if err := mode.Validate(); err != nil {
		return err
	}
	if realm != "" {
		d, err := principal.ParseRealm(string(realm))
		if err != nil {
			return err
		}
		if !d.IsGeneratedHost() && mode != EpithetPrincipalV1 {
			return fmt.Errorf("named realm %q requires %s", d, EpithetPrincipalV1)
		}
	}
	if mode == EpithetPrincipalV1 && realm == "" {
		return fmt.Errorf("realm is required for destination-bound principals")
	}
	seen := map[string]bool{}
	for _, a := range accounts {
		if a == "" || strings.ContainsAny(a, " \t\r\n,:") || strings.IndexFunc(a, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || seen[a] {
			return fmt.Errorf("invalid or duplicate account %q", a)
		}
		seen[a] = true
	}
	return nil
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
