package caserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

type caServer struct {
	c          *ca.CA
	httpClient *http.Client
	log        *slog.Logger
}

// New creates a new CA Server which needs to then
// be attached to some http server, a la
// `http.ListenAndServeTLS(...)`
func New(c *ca.CA, log *slog.Logger, httpClient *http.Client) http.Handler {
	cas := &caServer{
		c:          c,
		log:        log,
		httpClient: httpClient,
	}

	if cas.httpClient == nil {
		cas.httpClient = &http.Client{
			Timeout: time.Second * 30,
		}
	}

	return cas
}

func (s *caServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.getPubKey(w, r)
	case "POST":
		s.createCert(w, r)
	}
}

// CreateCertRequest asks for a signed cert
type CreateCertRequest struct {
	PublicKey  sshcert.RawPublicKey `json:"publicKey"`
	Token      string               `json:"token"`
	Connection policy.Connection    `json:"connection"`
}

// CreateCertResponse is response from a CreateCert request
type CreateCertResponse struct {
	Certificate sshcert.RawCertificate `json:"certificate"`
	Policy      policy.Policy          `json:"policy"`
}

// RequestBodySizeLimit is the maximum request body size
const RequestBodySizeLimit = 8192

func (s *caServer) createCert(w http.ResponseWriter, r *http.Request) {
	ccr := CreateCertRequest{}
	lr := io.LimitReader(r.Body, RequestBodySizeLimit)

	body, err := io.ReadAll(lr)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(400)
		w.Write(fmt.Appendf(nil, "unable to read body: %s", err))
		return
	}

	err = json.Unmarshal(body, &ccr)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(400)
		_, err := w.Write(fmt.Appendf(nil, "unable to parse body: %s", err))
		if err != nil {

		}
		return
	}

	policyResp, err := s.c.RequestPolicy(r.Context(), ccr.Token, ccr.Connection)
	if err != nil {
		// Check if it's a PolicyError with a specific status code
		var policyErr *ca.PolicyError
		if errors.As(err, &policyErr) {
			// Return the same status code the policy server returned
			w.Header().Add("Content-type", "text/plain")
			w.WriteHeader(policyErr.StatusCode)
			w.Write([]byte(policyErr.Message))
			return
		}
		// Other error - return 500
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(500)
		w.Write(fmt.Appendf(nil, "%s\nerror retrieving policy: %s", s.c.PolicyURL(), err))
		return
	}

	cert, err := s.c.SignPublicKey(ccr.PublicKey, &policyResp.CertParams)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(400)
		w.Write(fmt.Appendf(nil, "error generating crt: %s", err))
		return
	}

	resp := CreateCertResponse{
		Certificate: cert,
		Policy:      policyResp.Policy,
	}
	out, err := json.Marshal(&resp)
	if err != nil {
		w.WriteHeader(500)
		s.log.Warn("unable to jsonify response", "error", err)
		return
	}

	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(200)
	_, err = w.Write(out)
	if err != nil {
		s.log.Warn("unable to write response", "error", err)
		return
	}
}

func (s *caServer) getPubKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-type", "text/plain")
	w.WriteHeader(200)
	w.Write([]byte(s.c.PublicKey()))
}
