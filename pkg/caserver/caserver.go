package caserver

import (
	"context"
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
	"golang.org/x/crypto/ssh"
)

type caServer struct {
	c          *ca.CA
	httpClient *http.Client
	log        *slog.Logger
	certLogger CertLogger
}

// New creates a new CA Server which needs to then
// be attached to some http server, a la
// `http.ListenAndServeTLS(...)`
func New(c *ca.CA, log *slog.Logger, httpClient *http.Client, certLogger CertLogger) http.Handler {
	cas := &caServer{
		c:          c,
		log:        log,
		httpClient: httpClient,
		certLogger: certLogger,
	}

	if cas.httpClient == nil {
		cas.httpClient = &http.Client{
			Timeout: time.Second * 30,
		}
	}

	if cas.certLogger == nil {
		cas.certLogger = NewNoopCertLogger()
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

	// Log certificate issuance (best-effort)
	if err := s.logCertIssuance(r.Context(), cert, ccr.PublicKey, policyResp, ccr.Connection); err != nil {
		s.log.Warn("failed to log certificate issuance", "error", err)
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

// logCertIssuance logs a certificate issuance event with all metadata.
func (s *caServer) logCertIssuance(
	ctx context.Context,
	cert sshcert.RawCertificate,
	pubKey sshcert.RawPublicKey,
	policyResp *ca.PolicyResponse,
	conn policy.Connection,
) error {
	// Parse certificate to extract metadata
	parsedCert, err := parseCert(cert)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Generate public key fingerprint
	fingerprint, err := generateFingerprint(pubKey)
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}

	// Create cert event
	event := &CertEvent{
		Timestamp:            time.Now(),
		SerialNumber:         fmt.Sprintf("%d", parsedCert.Serial),
		Identity:             policyResp.CertParams.Identity,
		Principals:           policyResp.CertParams.Names,
		Connection:           conn,
		ValidAfter:           time.Unix(int64(parsedCert.ValidAfter), 0),
		ValidBefore:          time.Unix(int64(parsedCert.ValidBefore), 0),
		Extensions:           policyResp.CertParams.Extensions,
		PublicKeyFingerprint: fingerprint,
		Policy:               policyResp.Policy,
	}

	// Log the event (best-effort, non-blocking)
	return s.certLogger.LogCert(ctx, event)
}

// parseCert parses a raw SSH certificate to extract metadata.
func parseCert(cert sshcert.RawCertificate) (*ssh.Certificate, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
	if err != nil {
		return nil, err
	}

	sshCert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a certificate")
	}

	return sshCert, nil
}

// generateFingerprint generates an SSH fingerprint for a public key.
func generateFingerprint(pubKey sshcert.RawPublicKey) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return "", err
	}

	return ssh.FingerprintSHA256(key), nil
}
