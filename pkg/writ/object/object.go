// Package object defines the provider-independent objects consumed by Writ.
// Providers resolve identity, eligibility, and membership before returning these
// facts. This package owns selectable values and the boundary between defined
// fields and additional attributes; it knows nothing about provisioning schemas.
package object

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// Values is a fact's collection of strings. JSON and YAML may supply a single
// string, a string collection, or null. Null and empty collections contain no
// values; the empty string is a value. Non-string elements are always invalid.
type Values []string

func (v *Values) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if bytes.Equal(data, []byte("null")) {
		*v = nil
		return nil
	}
	var one string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &one); err != nil {
			return err
		}
		*v = Values{one}
		return nil
	}
	var raw []json.RawMessage
	if len(data) == 0 || data[0] != '[' {
		return fmt.Errorf("attribute value must be a string, string collection, or null")
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	out := make(Values, len(raw))
	for i, r := range raw {
		r = bytes.TrimSpace(r)
		if len(r) == 0 || r[0] != '"' {
			return fmt.Errorf("attribute collection must contain only strings")
		}
		if err := json.Unmarshal(r, &out[i]); err != nil {
			return err
		}
	}
	*v = out
	return nil
}

// UnmarshalYAML uses the decoder callback so shared facts do not link a YAML
// implementation. JSON and static YAML enforce the same string-only contract.
func (v *Values) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return v.UnmarshalJSON(data)
}

// Strings is a collection with no implicit conversion of scalar or null
// members. Unlike Values, the defined name field always uses an array.
type Strings []string

func (s *Strings) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || (data[0] != '[' && !bytes.Equal(data, []byte("null"))) {
		return fmt.Errorf("expected a string collection")
	}
	var values Values
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	*s = Strings(values)
	return nil
}

func (s *Strings) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return s.UnmarshalJSON(data)
}

// Attributes contains only additional, flat fields. Defined name/id fields
// cannot be shadowed by provider attributes.
type Attributes map[string]Values

func (a Attributes) Validate() error {
	for k := range a {
		if k == "name" || k == "id" {
			return fmt.Errorf("attribute %q must use the defined object field", k)
		}
	}
	return nil
}

// Object is a group membership's facts. ID is optional; Names is the set of
// names for this single object, not a set of unrelated same-named groups.
type Object struct {
	ID         string     `json:"id,omitempty" yaml:"id,omitempty"`
	Names      Strings    `json:"name" yaml:"name"`
	Attributes Attributes `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Values returns the complete values of an attribute on one object. Missing IDs
// supply no values. Defined fields always take precedence over additional data;
// Validate rejects collisions before any evaluation takes place.
func ValuesFor(id string, names []string, attrs Attributes, key string) []string {
	switch key {
	case "id":
		if id != "" {
			return []string{id}
		}
		return nil
	case "name":
		return names
	default:
		return attrs[key]
	}
}
func (o Object) Values(key string) []string { return ValuesFor(o.ID, o.Names, o.Attributes, key) }

// User is an eligible user resolved by a provider for an authenticated identity.
// UserName is certificate presentation, independent of selectable Names.
type User struct {
	ID         string     `json:"id" yaml:"id"`
	Names      Strings    `json:"name" yaml:"name"`
	UserName   string     `json:"userName,omitempty" yaml:"userName,omitempty"`
	Attributes Attributes `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	Groups     []Object   `json:"groups" yaml:"groups"`
}

func (u User) Values(key string) []string { return ValuesFor(u.ID, u.Names, u.Attributes, key) }
func (u User) Validate(authenticatedID string) error {
	if u.ID == "" || u.ID != authenticatedID {
		return fmt.Errorf("user does not match authenticated identity")
	}
	if err := u.Attributes.Validate(); err != nil {
		return err
	}
	for _, g := range u.Groups {
		if err := g.Attributes.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// GroupNames projects memberships for the existing name-based administration
// grants and displays. Authorization matching itself retains structured groups.
func GroupNames(groups []Object) []string {
	var names []string
	for _, g := range groups {
		names = append(names, g.Names...)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// FromStrings maps an adapter's single-valued attributes into the fact model.
func FromStrings(values map[string]string) Attributes {
	if values == nil {
		return nil
	}
	out := make(Attributes, len(values))
	for k, v := range values {
		out[k] = Values{v}
	}
	return out
}

// Memberships must be actual objects; a null element is not a group that can
// satisfy an empty group filter.
func (o *Object) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return fmt.Errorf("group must be an object")
	}
	type plain Object
	var out plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return err
	}
	*o = Object(out)
	return nil
}
