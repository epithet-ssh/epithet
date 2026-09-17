package scim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	userSchema       = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupSchema      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	enterpriseSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

// decodeDocument canonicalizes recognized attribute names, preserves extension
// values (including JSON numbers), and validates the supported fields.
// Protocol metadata is reconstructed from persisted state on every response.
func decodeDocument(kind Kind, data []byte) (Document, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("expected one JSON document")
	}
	if obj == nil {
		return nil, fmt.Errorf("expected a JSON object")
	}
	canonicalizeAttributes(obj)
	// Only known SCIM complex attributes have their field names normalized.
	// Unknown extension objects remain opaque.
	for _, key := range []string{"name", "emails", "members", "phoneNumbers", "addresses", "photos", "roles", "entitlements", "x509Certificates", enterpriseSchema} {
		canonicalizeAttributes(obj[key])
	}
	if enterprise, ok := obj[enterpriseSchema].(map[string]any); ok {
		canonicalizeAttributes(enterprise["manager"])
	}
	schemas, ok := obj["schemas"].([]any)
	if !ok {
		return nil, fmt.Errorf("schemas is required")
	}
	required := userSchema
	if kind == Groups {
		required = groupSchema
	}
	found := false
	for _, v := range schemas {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("invalid schema identifier")
		}
		found = found || s == required
	}
	if !found {
		return nil, fmt.Errorf("resource requires schema %s", required)
	}
	for _, key := range []string{"externalId", "userName", "displayName", "userType", "nickName", "title", "preferredLanguage", "locale", "timezone", "profileUrl"} {
		if v, exists := obj[key]; exists && v != nil {
			if _, ok := v.(string); !ok {
				return nil, fmt.Errorf("%s must be a string", key)
			}
		}
	}
	nonempty := func(key string) bool { s, _ := obj[key].(string); return strings.TrimSpace(s) != "" }
	if kind == Users {
		if !nonempty("userName") || !nonempty("externalId") {
			return nil, fmt.Errorf("userName and externalId are required")
		}
		if active, exists := obj["active"]; exists {
			if _, ok := active.(bool); !ok {
				return nil, fmt.Errorf("active must be a boolean")
			}
		} else {
			obj["active"] = true
		}
		if _, exists := obj["password"]; exists {
			return nil, fmt.Errorf("password provisioning is not supported")
		}
		if ext, exists := obj[enterpriseSchema]; exists {
			m, ok := ext.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("enterprise extension must be an object")
			}
			for _, key := range []string{"department", "organization"} {
				if v, ok := m[key]; ok && v != nil {
					if _, ok := v.(string); !ok {
						return nil, fmt.Errorf("%s must be a string", key)
					}
				}
			}
		}
		if name, exists := obj["name"]; exists && name != nil {
			fields, ok := name.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("name must be an object")
			}
			for _, key := range []string{"formatted", "givenName", "familyName", "middleName", "honorificPrefix", "honorificSuffix"} {
				if v := fields[key]; v != nil {
					if _, ok := v.(string); !ok {
						return nil, fmt.Errorf("name.%s must be a string", key)
					}
				}
			}
		}
		if emails, exists := obj["emails"]; exists && emails != nil {
			entries, ok := emails.([]any)
			if !ok {
				return nil, fmt.Errorf("emails must be an array")
			}
			primaries := 0
			for _, entry := range entries {
				fields, ok := entry.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("email must be an object")
				}
				for _, key := range []string{"value", "display", "type"} {
					if v := fields[key]; v != nil {
						if _, ok := v.(string); !ok {
							return nil, fmt.Errorf("emails.%s must be a string", key)
						}
					}
				}
				if v, exists := fields["primary"]; exists {
					primary, ok := v.(bool)
					if !ok {
						return nil, fmt.Errorf("emails.primary must be a boolean")
					}
					if primary {
						primaries++
					}
				}
			}
			if primaries > 1 {
				return nil, fmt.Errorf("only one primary email is allowed")
			}
		}
		// User.groups is read-only; group resources own membership.
		delete(obj, "groups")
	} else {
		if !nonempty("displayName") {
			return nil, fmt.Errorf("displayName is required")
		}
		if m, exists := obj["members"]; exists && m != nil {
			members, ok := m.([]any)
			if !ok {
				return nil, fmt.Errorf("members must be an array")
			}
			unique := make([]any, 0, len(members))
			seen := map[string]bool{}
			for _, v := range members {
				member, ok := v.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("invalid member")
				}
				id, ok := member["value"].(string)
				if !ok || id == "" {
					return nil, fmt.Errorf("member value is required")
				}
				if typ, exists := member["type"]; exists && typ != "User" {
					return nil, fmt.Errorf("only direct User memberships are supported")
				}
				if !seen[id] {
					unique = append(unique, member)
					seen[id] = true
				}
			}
			obj["members"] = unique
		} else {
			obj["members"] = []any{}
		}
	}
	delete(obj, "id")
	delete(obj, "meta")
	out := Document{}
	for k, v := range obj {
		b, e := json.Marshal(v)
		if e != nil {
			return nil, e
		}
		out[k] = b
	}
	return out, nil
}

var canonicalNames = func() map[string]string {
	m := map[string]string{strings.ToLower(enterpriseSchema): enterpriseSchema}
	for _, k := range strings.Fields("schemas id meta externalId userName displayName userType active password groups members value display type $ref primary name formatted givenName familyName middleName honorificPrefix honorificSuffix emails phoneNumbers addresses streetAddress locality region postalCode country department organization employeeNumber costCenter division manager nickName title preferredLanguage locale timezone profileUrl photos roles entitlements x509Certificates") {
		m[strings.ToLower(k)] = k
	}
	return m
}()

// canonicalizeAttributes normalizes one object or each object in a multivalued
// attribute. It does not descend into object fields.
func canonicalizeAttributes(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, v := range value {
			if name, ok := canonicalNames[strings.ToLower(key)]; ok && name != key {
				delete(value, key)
				value[name] = v
			}
		}
	case []any:
		for _, item := range value {
			canonicalizeAttributes(item)
		}
	}
}
