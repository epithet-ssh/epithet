package caserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
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
// `http.ListenAndServeTLS(...)`.
func New(c *ca.CA, log *slog.Logger, httpClient *http.Client, certLogger CertLogger) *caServer {
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

// Handler returns an http.Handler that serves the CA's root endpoint.
// GET / returns the CA public key.
// POST / creates a certificate.
func (s *caServer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			s.getPubKey(w, r)
		case "POST":
			s.createCert(w, r)
		default:
			s.fail(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})
}

// DiscoveryHandler returns an http.Handler that serves the /discovery
// endpoint: an anonymous pass-through of the policy server's auth config.
// There is no authenticated variant — clients need this before they have a
// token, so it is never gated.
func (s *caServer) DiscoveryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			s.fail(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		discovery, err := s.c.FetchDiscovery(r.Context())
		if err != nil {
			s.log.Warn("failed to fetch discovery from policy server", "error", err)
			s.fail(w, http.StatusBadGateway, "failed to fetch discovery: %v", err)
			return
		}

		resp := &wire.Discovery{Auth: discovery.Auth}

		out, err := json.Marshal(resp)
		if err != nil {
			s.log.Warn("unable to jsonify discovery response", "error", err)
			s.fail(w, http.StatusInternalServerError, "unable to jsonify discovery response")
			return
		}

		// Pass through the policy server's Cache-Control header so clients
		// respect the upstream's caching intent. Fall back to 5 minutes.
		cc := discovery.CacheControl
		if cc == "" {
			cc = "max-age=300"
		}
		w.Header().Set("Cache-Control", cc)
		w.Header().Add("Content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(out)
	})
}

// fail writes a plain-text error response.
func (s *caServer) fail(w http.ResponseWriter, code int, format string, args ...any) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	fmt.Fprintf(w, format, args...)
}

// CreateCertRequest asks for a signed cert. Both fields are required.
type CreateCertRequest struct {
	PublicKey  sshcert.RawPublicKey `json:"publicKey"`
	Connection policy.Connection    `json:"connection"`
}

// CreateCertResponse is response from a CreateCert request.
type CreateCertResponse struct {
	Certificate sshcert.RawCertificate `json:"certificate"`
	Policy      policy.Policy          `json:"policy"`
}

// RequestBodySizeLimit is the maximum request body size.
const RequestBodySizeLimit = 8192

// parseAuthHeader extracts the Bearer token from the Authorization header.
func parseAuthHeader(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", errors.New("missing Authorization header")
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", errors.New("Authorization header must use Bearer scheme")
	}

	token := strings.TrimPrefix(auth, prefix)
	if token == "" {
		return "", errors.New("empty Bearer token")
	}

	return token, nil
}

func (s *caServer) createCert(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header.
	token, err := parseAuthHeader(r)
	if err != nil {
		s.fail(w, http.StatusUnauthorized, "%s", err.Error())
		return
	}

	ccr := CreateCertRequest{}
	lr := io.LimitReader(r.Body, RequestBodySizeLimit)

	body, err := io.ReadAll(lr)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "unable to read body: %s", err)
		return
	}

	err = json.Unmarshal(body, &ccr)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "unable to parse body: %s", err)
		return
	}

	if ccr.PublicKey == "" || ccr.Connection.RemoteHost == "" {
		s.fail(w, http.StatusBadRequest, "publicKey and connection.remoteHost are required")
		return
	}

	policyResp, err := s.c.RequestPolicy(r.Context(), token, ccr.Connection)
	if err != nil {
		var policyErr *wire.PolicyError
		if errors.As(err, &policyErr) {
			s.fail(w, policyErr.StatusCode, "%s", policyErr.Message)
			return
		}
		s.fail(w, http.StatusInternalServerError, "%s\nerror retrieving policy: %s", s.c.PolicyURL(), err)
		return
	}

	cert, err := s.c.SignPublicKey(ccr.PublicKey, &policyResp.CertParams)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "error generating crt: %s", err)
		return
	}

	// Log certificate issuance (best-effort).
	if err := s.logCertIssuance(r.Context(), cert, ccr.PublicKey, policyResp, ccr.Connection); err != nil {
		s.log.Warn("failed to log certificate issuance", "error", err)
	}

	resp := CreateCertResponse{
		Certificate: cert,
		Policy:      policyResp.Policy,
	}
	out, err := json.Marshal(&resp)
	if err != nil {
		s.log.Warn("unable to jsonify response", "error", err)
		s.fail(w, http.StatusInternalServerError, "unable to jsonify response")
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
	policyResp *wire.PolicyResponse,
	conn policy.Connection,
) error {
	parsedCert, err := parseCert(cert)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	fingerprint, err := generateFingerprint(pubKey)
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}

	// Cert fingerprint matches what `epithet agent inspect` displays.
	certFP := "SHA256:" + base64.RawStdEncoding.EncodeToString(sha256Sum(parsedCert.Marshal()))

	event := &CertEvent{
		Timestamp:            time.Now(),
		SerialNumber:         fmt.Sprintf("%d", parsedCert.Serial),
		Identity:             policyResp.CertParams.Identity,
		Principals:           policyResp.CertParams.Names,
		Connection:           conn,
		ValidAfter:           time.Unix(int64(parsedCert.ValidAfter), 0),
		ValidBefore:          time.Unix(int64(parsedCert.ValidBefore), 0),
		Extensions:           policyResp.CertParams.Extensions,
		CertFingerprint:      certFP,
		PublicKeyFingerprint: fingerprint,
		Policy:               policyResp.Policy,
	}

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

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
