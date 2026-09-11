package wire

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
)

// PolicyFacts is CA's normalized input for one requested target. CA validates
// the inventory's host/domain binding before projecting Host. Host.Names lists the
// equivalent host names or the shared principal domain; Target binds the request.
// Principal construction data, revisions, and protocol versions remain at CA.
type PolicyFacts struct {
	Authentication facts.Authentication `json:"authentication"`
	Target         string               `json:"target"`
	User           *facts.User          `json:"user"`
	Host           *facts.HostResource  `json:"host"`
}

// Validate preserves identity, connection binding, and authentication lifetime.
// Explicit null records represent absence for policy's structural denial.
func (f *PolicyFacts) Validate(requestedHost string) error {
	if f == nil {
		return fmt.Errorf("policy facts are required")
	}
	if f.Target == "" || f.Target != hostpattern.NormalizeName(requestedHost) {
		return fmt.Errorf("policy facts do not match requested target")
	}
	if err := f.Authentication.Validate(); err != nil {
		return err
	}
	if f.User != nil {
		if err := f.User.Validate(f.Authentication.ID); err != nil {
			return err
		}
	}
	if f.Host != nil {
		if err := f.Host.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalJSON distinguishes explicit absent records from omitted fields and
// retains strict decoding even though this type has custom unmarshalling.
func (f *PolicyFacts) UnmarshalJSON(data []byte) error {
	type plain PolicyFacts
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"user", "host"} {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("policy %s field is required", name)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode((*plain)(f))
}
