package caserver

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/brianm/epithet/pkg/ca"
	"github.com/brianm/epithet/pkg/sshcert"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/sirupsen/logrus"
)

// New creates a new CA Server which needs to then
// be atatched to some http server, a la
// `http.ListenAndServeTLS(...)`
func New(c *ca.CA) http.Handler {
	cas := &caServer{
		c: c,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", cas.GetPubKey)
	r.Post("/", cas.CreateCert)

	return r
}

type caServer struct {
	c *ca.CA
}

// CreateCertRequest asks for a signed cert
type CreateCertRequest struct {
	PublicKey     sshcert.RawPublicKey `json:"publicKey"`
	AuthnProvider string               `json:"authenticationProvider"` // on refresh will be "refresh"
	Token         string               `json:"token"`
}

// CreateCertResponse is response from a CreateCert request
type CreateCertResponse struct {
	SessionToken string                 `json:"refreshToken"`
	Certificate  sshcert.RawCertificate `json:"certificate"`
}

// RequestBodySizeLimit is the maximum request body size
const RequestBodySizeLimit = 8192

func (s *caServer) CreateCert(w http.ResponseWriter, r *http.Request) {
	ccr := CreateCertRequest{}
	lr := io.LimitReader(r.Body, RequestBodySizeLimit)

	body, err := ioutil.ReadAll(lr)
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

	cert, err := s.c.SignPublicKey(ccr.PublicKey, &ca.CertParams{
		Identity:   "brianm",
		Names:      []string{"root", "brianm"},
		Expiration: time.Until(time.Now().Add(time.Hour)),
	})

	if err != nil {
		w.Header().Add("Content-type", "text/plain")
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf("error generating crt: %s", err)))
		return
	}

	resp := CreateCertResponse{
		SessionToken: "abc123",
		Certificate:  cert,
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

func (s *caServer) GetPubKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-type", "text/plain")
	w.WriteHeader(200)
	w.Write([]byte(s.c.PublicKey()))
}
