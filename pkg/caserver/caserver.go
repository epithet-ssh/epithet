package caserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/sirupsen/logrus"
)

type caServer struct {
	c          *ca.CA
	httpClient *http.Client
}

// New creates a new CA Server which needs to then
// be atatched to some http server, a la
// `http.ListenAndServeTLS(...)`
func New(c *ca.CA, options ...Option) http.Handler {
	cas := &caServer{
		c: c,
	}

	for _, o := range options {
		o.apply(cas)
	}

	if cas.httpClient == nil {
		cas.httpClient = &http.Client{
			Timeout: time.Second * 30,
		}
	}

	return cas
}

// Option configures the agent
type Option interface {
	apply(*caServer)
}

type optionFunc func(*caServer)

func (f optionFunc) apply(a *caServer) {
	f(a)
}

// WithHTTPClient specifies the http client to use
func WithHTTPClient(httpClient *http.Client) Option {
	return optionFunc(func(s *caServer) {
		s.httpClient = httpClient
	})
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
	PublicKey sshcert.RawPublicKey `json:"publicKey"`
	Token     string               `json:"token"`
}

// CreateCertResponse is response from a CreateCert request
type CreateCertResponse struct {
	Certificate sshcert.RawCertificate `json:"certificate"`
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
		w.Write([]byte(fmt.Sprintf("unable to read body: %s", err)))
		return
	}

	err = json.Unmarshal(body, &ccr)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf("unable to parse body: %s", err)))
		return
	}

	params, err := s.c.RequestPolicy(r.Context(), ccr.Token)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf("%s\nerror retrieving policy: %s", s.c.PolicyURL(), err)))
		return
	}

	cert, err := s.c.SignPublicKey(ccr.PublicKey, params)
	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf("error generating crt: %s", err)))
		return
	}

	resp := CreateCertResponse{
		Certificate: cert,
	}
	out, err := json.Marshal(&resp)
	if err != nil {
		w.WriteHeader(500)
		logrus.Warn("unable to jsonify response: %w", err)
		return
	}

	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(200)
	_, err = w.Write(out)
	if err != nil {
		logrus.Warn("unable to write response: %w", err)
		return
	}
}

func (s *caServer) getPubKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-type", "text/plain")
	w.WriteHeader(200)
	w.Write([]byte(s.c.PublicKey()))
}
