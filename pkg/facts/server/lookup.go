package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net/http"
	"net/url"

	"github.com/epithet-ssh/epithet/pkg/directory"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// LookupHandler serves one kind of fact; directory and inventory use separate
// audiences and transports. Either the CA reader or control key may read.
func LookupHandler(users directory.Directory, hosts inventory.Hosts, caKey, controlKey sshcert.RawPublicKey) (http.Handler, error) {
	if (users == nil) == (hosts == nil) {
		return nil, fmt.Errorf("exactly one fact source is required")
	}
	if caKey != "" && controlKey != "" {
		ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey))
		if err != nil {
			return nil, err
		}
		control, _, _, _, err := ssh.ParseAuthorizedKey([]byte(controlKey))
		if err != nil {
			return nil, err
		}
		if bytes.Equal(ca.Marshal(), control.Marshal()) {
			return nil, fmt.Errorf("CA and control must use distinct signing keys")
		}
	}
	audience, param := facts.InventoryAudience, "host"
	if users != nil {
		audience, param = facts.DirectoryAudience, "id"
	}
	var verifiers []*facts.Verifier
	for _, key := range []sshcert.RawPublicKey{caKey, controlKey} {
		if key == "" {
			continue
		}
		v, err := facts.NewVerifierFor(key, audience)
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, v)
	}
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("fact readers require a trusted public key")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		defer r.Body.Close()
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(data) != 0 {
			http.Error(w, "lookup must not have a body", 400)
			return
		}
		valid := false
		for _, v := range verifiers {
			if v.Verify(r, nil) == nil {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "invalid service authentication", 403)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query) != 1 || len(query[param]) != 1 || query.Get(param) == "" {
			http.Error(w, "one lookup key is required", 400)
			return
		}
		value := query.Get(param)
		var response any
		if users != nil {
			u, revision, e := users.LookupUser(r.Context(), value)
			err = e
			if err == nil && u != nil && u.Active {
				response = &userFacts{User: facts.User{ID: u.ID, UserName: u.UserName, Groups: u.Groups, UserType: u.UserType, Department: u.Department, Organization: u.Organization}, Revision: string(revision)}
			}
		} else {
			if value != hostpattern.NormalizeName(value) {
				http.Error(w, "host must be normalized", 400)
				return
			}
			h, revision, e := hosts.LookupHost(r.Context(), value)
			err = e
			if err == nil && h != nil {
				response = &hostFacts{Host: wire.Host{HostResource: wire.HostResource{Names: h.Policy.Names, Labels: h.Policy.Labels, Accounts: h.Policy.Accounts}, Principal: wire.Principal{Mode: string(h.PrincipalMode.Effective()), Realm: string(h.Realm)}}, Revision: string(revision)}
			}
		}
		if err != nil {
			if errors.Is(err, inventory.ErrConflict) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			http.Error(w, "fact service unavailable", 503)
			return
		}
		if response == nil {
			http.NotFound(w, r)
			return
		}
		data, err = json.Marshal(response)
		if err != nil || len(data) > wire.MaxBodySize {
			http.Error(w, "invalid or oversized facts", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}), nil
}

// Stores omit empty revision metadata. The client representation separately
// validates and preserves the presence of revisions supplied by any provider.
type userFacts struct {
	facts.User
	Revision string `json:"revision,omitempty"`
}

type hostFacts struct {
	wire.Host
	Revision string `json:"revision,omitempty"`
}
