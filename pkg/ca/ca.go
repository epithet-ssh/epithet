package ca

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"golang.org/x/crypto/ssh"
)

// CA performs CA operations.
type CA struct {
	facts      *facts.DataClient
	validator  *oidc.Validator
	discovery  *wire.Discovery
	evaluator  PolicyEvaluator
	signer     ssh.Signer
	privateKey sshcert.RawPrivateKey
	logger     *slog.Logger
}

// certParams are assembled by CA from trusted inventory and policy limits.
// They are local signing inputs, not the policy service's wire contract.
type certParams struct {
	Identity   string
	Names      []string
	Expiration time.Duration
	Extensions map[string]string
	// NotAfter is the optional absolute deadline supplied by policy.
	NotAfter time.Time
}

// AuditMetadata identifies the identity and source revisions used for issuance.
type AuditMetadata struct {
	ID                string
	PolicyID          string
	DirectoryRevision string
	InventoryRevision string
}

// IssuedCertificate contains a signed certificate and its private audit metadata.
// Audit metadata is for server-side logging and is not part of the client response.
type IssuedCertificate struct {
	Certificate sshcert.RawCertificate
	Audit       AuditMetadata
}

type authorization struct {
	audit  AuditMetadata
	params certParams
}

// Issue obtains policy approval and signs the requested key using inventory facts
// and policy-provided limits. It returns a result only after signing succeeds;
// callers never handle intermediate authorization or signing parameters.
func (c *CA) Issue(ctx context.Context, token string, conn wire.Connection, publicKey sshcert.RawPublicKey) (*IssuedCertificate, error) {
	auth, err := c.requestPolicy(ctx, token, conn)
	if err != nil {
		return nil, fmt.Errorf("certificate authorization failed: %w", err)
	}
	cert, err := c.signPublicKey(publicKey, &auth.params)
	if err != nil {
		return nil, fmt.Errorf("certificate signing failed: %w", err)
	}
	return &IssuedCertificate{Certificate: cert, Audit: auth.audit}, nil
}

// New creates the issuing authority with its in-process policy evaluator.
func New(privateKey sshcert.RawPrivateKey, evaluator PolicyEvaluator, options ...Option) (*CA, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}
	c := &CA{signer: signer, privateKey: privateKey, evaluator: evaluator}
	for _, o := range options {
		if err := o.apply(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Option configures the CA.
type Option interface {
	apply(*CA) error
}

type optionFunc func(*CA) error

func (f optionFunc) apply(a *CA) error {
	return f(a)
}

// WithLogger configures the CA to use the specified logger.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *CA) error {
		c.logger = logger
		return nil
	})
}

// PublicKey returns the ssh on-disk format public key for the CA.
func (c *CA) PublicKey() sshcert.RawPublicKey {
	pk := c.signer.PublicKey()
	return sshcert.RawPublicKey(string(ssh.MarshalAuthorizedKey(pk)))
}

// FetchDiscovery returns this CA's configured login information.
func (c *CA) FetchDiscovery(context.Context) (*wire.Discovery, error) {
	if c.discovery == nil {
		return nil, fmt.Errorf("CA authentication is not configured")
	}
	d := *c.discovery
	if d.Auth != nil {
		a := *d.Auth
		d.Auth = &a
	}
	return &d, nil
}

// requestPolicy authenticates, fetches current facts, and evaluates Writ in this
// process. Neither fact provider receives the end user's bearer credential.
func (c *CA) requestPolicy(ctx context.Context, token string, conn wire.Connection) (*authorization, error) {
	ctx, cancel := context.WithTimeout(ctx, tlsconfig.DefaultTimeout)
	defer cancel()
	if c.validator == nil || c.facts == nil || c.evaluator == nil {
		return nil, fmt.Errorf("CA issuance is not configured")
	}
	claims, err := c.validator.Validate(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAuthentication, err)
	}
	name := hostpattern.NormalizeName(conn.RemoteHost)
	user, err := c.facts.User(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: directory lookup: %w", ErrDependency, err)
	}
	if user == nil {
		return nil, ErrAccessDenied
	}
	host, err := c.facts.Host(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("%w: inventory lookup: %w", ErrDependency, err)
	}
	if host == nil {
		return nil, ErrAccessDenied
	}
	if c.logger != nil {
		if !user.Revision.IsZero() {
			c.logger.Info("directory lookup", "id", user.ID, "revision", user.Revision.String())
		}
		if !host.Revision.IsZero() {
			c.logger.Info("inventory lookup", "host", name, "revision", host.Revision.String())
		}
	}
	active := true
	facts := &wire.PolicyFacts{Authentication: wire.Authentication{ID: claims.UserID, ExpiresAt: claims.ExpiresAt}, Target: name,
		User: &wire.User{ID: user.ID, UserName: user.UserName, Active: &active, Groups: user.Groups, UserType: user.UserType, Department: user.Department, Organization: user.Organization}, Host: &host.HostResource}
	response, err := c.evaluator.Evaluate(ctx, conn, facts)
	if err != nil {
		kind := ErrDependency
		var e *wire.PolicyError
		if errors.As(err, &e) {
			if e.StatusCode == http.StatusForbidden {
				kind = ErrAccessDenied
			} else if e.StatusCode == http.StatusAccepted {
				kind = ErrAuthorizationPending
			}
		}
		return nil, fmt.Errorf("%w: %w", kind, err)
	}
	if response == nil || conn.RemoteUser == "" {
		return nil, fmt.Errorf("%w: policy approval lacks signing data", ErrDependency)
	}
	expected := conn.RemoteUser
	if host.Principal.Mode == "epithet-principal-v1" {
		expected, err = principal.DeriveV1(principal.Realm(host.Principal.Realm), conn.RemoteUser)
		if err != nil {
			return nil, err
		}
	}
	if response.TTLSeconds <= 0 || response.TTLSeconds > wire.MaxTTLSeconds {
		return nil, fmt.Errorf("%w: invalid policy TTL", ErrDependency)
	}
	deadline := claims.ExpiresAt
	if !response.NotAfter.IsZero() && response.NotAfter.Before(deadline) {
		deadline = response.NotAfter
	}
	if !deadline.After(time.Now()) {
		return nil, fmt.Errorf("%w: certificate deadline has expired", ErrDependency)
	}
	identity := user.UserName
	if identity == "" {
		identity = user.ID
	}
	return &authorization{audit: AuditMetadata{ID: user.ID, PolicyID: response.PolicyID, DirectoryRevision: user.Revision.String(), InventoryRevision: host.Revision.String()}, params: certParams{Identity: identity, Names: []string{expected}, Expiration: time.Duration(response.TTLSeconds) * time.Second, Extensions: response.Extensions, NotAfter: deadline}}, nil
}

// signPublicKey signs a key to generate a certificate.
func (c *CA) signPublicKey(rawPubKey sshcert.RawPublicKey, params *certParams) (sshcert.RawCertificate, error) {
	if params.Expiration <= 0 {
		return "", fmt.Errorf("certificate lifetime must be positive")
	}

	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	serial := binary.LittleEndian.Uint64(buf)

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawPubKey))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
	}

	// Anchor TTL at signing, after key parsing and entropy acquisition. Recheck
	// absolute limits here because authorization may have expired since lookup.
	now := time.Now()
	if !params.NotAfter.IsZero() && !params.NotAfter.After(now) {
		return "", fmt.Errorf("certificate NotAfter %s is in the past", params.NotAfter)
	}
	validBefore := now.Add(params.Expiration)
	if !params.NotAfter.IsZero() && params.NotAfter.Before(validBefore) {
		validBefore = params.NotAfter
	}
	if validBefore.Unix() <= now.Unix() {
		return "", fmt.Errorf("certificate expiry leaves no usable lifetime")
	}

	certificate := ssh.Certificate{
		Serial:          serial,
		Key:             pubKey,
		KeyId:           params.Identity,
		ValidPrincipals: params.Names,
		ValidAfter:      uint64(now.Unix() - 60),
		ValidBefore:     uint64(validBefore.Unix()),
		CertType:        ssh.UserCert,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      params.Extensions,
		},
	}
	err = certificate.SignCert(rand.Reader, c.signer)
	if err != nil {
		return "", err
	}
	rawCert := ssh.MarshalAuthorizedKey(&certificate)
	if len(rawCert) == 0 {
		return "", errors.New("unknown problem marshaling certificate")
	}
	return sshcert.RawCertificate(string(rawCert)), nil
}

// WithFacts configures independent read providers and CA-owned OIDC validation.
func WithFacts(directoryURL, inventoryURL string, identity oidc.ValidatorConfig, discovery wire.AuthConfig, cfg tlsconfig.Config) Option {
	return optionFunc(func(c *CA) error {
		var err error
		if directoryURL == "" || inventoryURL == "" {
			return fmt.Errorf("directory and inventory lookup endpoints are required")
		}
		c.facts, err = facts.NewDataClient(directoryURL, inventoryURL, c.privateKey, cfg)
		if err != nil {
			return err
		}
		c.validator, err = oidc.NewValidator(context.Background(), identity)
		if err != nil {
			return err
		}
		c.discovery = &wire.Discovery{Auth: &discovery, CacheControl: "max-age=300"}
		return nil
	})
}
