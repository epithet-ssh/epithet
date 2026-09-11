package caserver

import (
	"context"
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

// relAuth is the extension relation type advertising the CA's auth config
// document. Duplicated rather than shared with pkg/caclient: the wire value is
// the contract between them, and importing one from the other would couple the
// server to the client package.
const relAuth = "https://epithet.dev/rel/auth"

type caServer struct {
	c          *ca.CA
	log        *slog.Logger
	certLogger CertLogger
}

// New creates a new CA Server which needs to then
// be attached to some http server, a la
// `http.ListenAndServeTLS(...)`.
func New(c *ca.CA, log *slog.Logger, certLogger CertLogger) *caServer {
	cas := &caServer{
		c:          c,
		log:        log,
		certLogger: certLogger,
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
			s.fail(w, http.StatusMethodNotAllowed)
		}
	})
}

// DiscoveryHandler returns an http.Handler that serves the /discovery
// endpoint: an anonymous pass-through of the inventory service's auth config.
// There is no authenticated variant — clients need this before they have a
// token, so it is never gated.
func (s *caServer) DiscoveryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			s.fail(w, http.StatusMethodNotAllowed)
			return
		}

		discovery, err := s.c.FetchDiscovery(r.Context())
		if err != nil {
			s.log.Warn("failed to fetch discovery from inventory service", "error", err)
			s.failError(w, err)
			return
		}

		resp := &wire.Discovery{Auth: discovery.Auth}

		out, err := json.Marshal(resp)
		if err != nil {
			s.log.Warn("unable to jsonify discovery response", "error", err)
			s.fail(w, http.StatusInternalServerError)
			return
		}

		// Pass through the inventory service's Cache-Control header so clients
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

// fail writes only fixed public messages. Diagnostics must be logged separately.
func (s *caServer) fail(w http.ResponseWriter, code int) {
	message := ""
	switch code {
	case http.StatusAccepted:
		message = "authorization pending; try again later"
	case http.StatusBadRequest:
		message = "invalid certificate request"
	case http.StatusUnauthorized:
		message = "invalid or expired authentication"
	case http.StatusForbidden:
		message = "access denied"
	case http.StatusMethodNotAllowed:
		message = "method not allowed"
	case http.StatusRequestEntityTooLarge:
		message = "request too large"
	case http.StatusBadGateway:
		message = "CA dependency unavailable"
	default:
		code = http.StatusInternalServerError
		message = "internal CA error"
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	io.WriteString(w, message)
}

// failError maps trusted CA error classes, never upstream HTTP statuses or bodies.
func (s *caServer) failError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, ca.ErrInvalidAuthentication):
		code = http.StatusUnauthorized
	case errors.Is(err, ca.ErrAccessDenied):
		code = http.StatusForbidden
	case errors.Is(err, ca.ErrAuthorizationPending):
		code = http.StatusAccepted
	case errors.Is(err, ca.ErrDependency):
		code = http.StatusBadGateway
	case errors.Is(err, ca.ErrInvalidPublicKey):
		code = http.StatusBadRequest
	}
	s.fail(w, code)
}

// CreateCertRequest asks for a signed cert. Both fields are required.
type CreateCertRequest struct {
	PublicKey  sshcert.RawPublicKey `json:"publicKey"`
	Connection policy.Connection    `json:"connection"`
}

// CreateCertResponse is response from a CreateCert request.
type CreateCertResponse struct {
	Certificate sshcert.RawCertificate `json:"certificate"`
}

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
		s.log.Warn("invalid authorization header", "error", err)
		s.fail(w, http.StatusUnauthorized)
		return
	}

	ccr := CreateCertRequest{}
	body, err := io.ReadAll(io.LimitReader(r.Body, wire.MaxBodySize+1))
	if err != nil {
		s.log.Warn("unable to read certificate request", "error", err)
		s.fail(w, http.StatusBadRequest)
		return
	}

	// Check if request body exceeds the limit to report a distinct "too large"
	// error instead of a confusing JSON parse failure.
	if len(body) > wire.MaxBodySize {
		s.fail(w, http.StatusRequestEntityTooLarge)
		return
	}

	err = json.Unmarshal(body, &ccr)
	if err != nil {
		s.log.Warn("unable to parse certificate request", "error", err)
		s.fail(w, http.StatusBadRequest)
		return
	}

	if ccr.PublicKey == "" || ccr.Connection.RemoteHost == "" || ccr.Connection.RemoteUser == "" {
		s.log.Warn("certificate request requires publicKey, connection.remoteHost, and connection.remoteUser")
		s.fail(w, http.StatusBadRequest)
		return
	}

	policyResp, err := s.c.RequestPolicy(r.Context(), token, ccr.Connection)
	if err != nil {
		s.log.Warn("certificate authorization failed", "error", err)
		s.failError(w, err)
		return
	}

	cert, err := s.c.SignPublicKey(ccr.PublicKey, &policyResp.CertParams)
	if err != nil {
		s.log.Warn("certificate signing failed", "error", err)
		s.failError(w, err)
		return
	}

	// Log certificate issuance (best-effort).
	if err := s.logCertIssuance(r.Context(), cert, ccr.PublicKey, policyResp, ccr.Connection); err != nil {
		s.log.Warn("failed to log certificate issuance", "error", err)
	}

	resp := CreateCertResponse{
		Certificate: cert,
	}
	out, err := json.Marshal(&resp)
	if err != nil {
		s.log.Warn("unable to jsonify response", "error", err)
		s.fail(w, http.StatusInternalServerError)
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
	// Advertise the auth config with a relative target so the CA needs no
	// knowledge of its own external URL: the client resolves it against the
	// ca-url it already has. See ideas/link-header-auth-discovery.md.
	w.Header().Set("Link", `<discovery>; rel="`+relAuth+`"`)
	w.Header().Add("Content-type", "text/plain")
	w.WriteHeader(200)
	w.Write([]byte(s.c.PublicKey()))
}

// logCertIssuance logs a certificate issuance event with all metadata.
func (s *caServer) logCertIssuance(
	ctx context.Context,
	cert sshcert.RawCertificate,
	pubKey sshcert.RawPublicKey,
	policyResp *ca.Authorization,
	conn policy.Connection,
) error {
	parsedCert, err := sshcert.Parse(cert)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	fingerprint, err := generateFingerprint(pubKey)
	if err != nil {
		return fmt.Errorf("failed to generate fingerprint: %w", err)
	}

	// Cert fingerprint matches what `epithet agent inspect` displays.
	certFP := ssh.FingerprintSHA256(parsedCert)

	event := &CertEvent{
		PolicyID: policyResp.PolicyID, DirectoryRevision: policyResp.DirectoryRevision, InventoryRevision: policyResp.InventoryRevision,
		Timestamp:            time.Now(),
		SerialNumber:         fmt.Sprintf("%d", parsedCert.Serial),
		UserName:             policyResp.CertParams.Identity,
		ID:                   policyResp.ID,
		Principals:           policyResp.CertParams.Names,
		Connection:           conn,
		ValidAfter:           time.Unix(int64(parsedCert.ValidAfter), 0),
		ValidBefore:          time.Unix(int64(parsedCert.ValidBefore), 0),
		Extensions:           policyResp.CertParams.Extensions,
		CertFingerprint:      certFP,
		PublicKeyFingerprint: fingerprint,
	}

	return s.certLogger.LogCert(ctx, event)
}

// generateFingerprint generates an SSH fingerprint for a public key.
func generateFingerprint(pubKey sshcert.RawPublicKey) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return "", err
	}

	return ssh.FingerprintSHA256(key), nil
}
