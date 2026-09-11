package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/hostpattern"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"github.com/epithet-ssh/epithet/pkg/inventoryserver"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/serviceauth"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"golang.org/x/crypto/ssh"
)

// CA performs CA operations.
type CA struct {
	inventory  *inventoryserver.Client
	signer     ssh.Signer
	privateKey sshcert.RawPrivateKey
	policyURL  string
	httpClient *http.Client
	logger     *slog.Logger

	// svcSigner mints the request-bound JWT sent to the policy server.
	svcSigner *serviceauth.Signer
}

// CertParams are assembled by CA from trusted inventory and policy limits.
// They are local signing inputs, not the policy service's wire contract.
type CertParams struct {
	Identity   string
	Names      []string
	Expiration time.Duration
	Extensions map[string]string
	// NotAfter is the earlier of authentication expiry and any policy deadline.
	NotAfter time.Time
}

// Authorization holds CA's signing inputs and private issuance audit metadata.
type Authorization struct {
	ID                string
	PolicyID          string
	DirectoryRevision string
	InventoryRevision string
	CertParams        CertParams
}

// PolicyURL returns the URL of the policy server.
func (c *CA) PolicyURL() string {
	return c.policyURL
}

// New creates a new CA.
func New(privateKey sshcert.RawPrivateKey, policyURL string, options ...Option) (*CA, error) {
	sshSigner, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	svcSigner, err := serviceauth.NewSigner(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create service auth signer: %w", err)
	}

	ca := &CA{
		signer:     sshSigner,
		privateKey: privateKey,
		policyURL:  policyURL,
		svcSigner:  svcSigner,
	}

	for _, o := range options {
		if err := o.apply(ca); err != nil {
			return nil, err
		}
	}

	if ca.httpClient == nil {
		ca.httpClient = &http.Client{
			Timeout: tlsconfig.DefaultTimeout,
		}
	}

	ca.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// When the policy URL is a unix socket, configure the HTTP transport to
	// dial the socket and rewrite the URL to http://localhost.
	if socketPath, ok := strings.CutPrefix(ca.policyURL, "unix://"); ok {
		dialFunc := func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}
		ca.httpClient.Transport = &http.Transport{DialContext: dialFunc}

		ca.policyURL = "http://localhost/"
	}

	return ca, nil
}

// Option configures the CA.
type Option interface {
	apply(*CA) error
}

type optionFunc func(*CA) error

func (f optionFunc) apply(a *CA) error {
	return f(a)
}

// WithTLSConfig creates an HTTP client with the specified TLS configuration,
// using tlsconfig's shared default timeout rather than a locally-duplicated
// literal.
func WithTLSConfig(cfg tlsconfig.Config) Option {
	return optionFunc(func(c *CA) error {
		httpClient, err := tlsconfig.NewHTTPClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to create HTTP client: %w", err)
		}
		c.httpClient = httpClient
		return nil
	})
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

// FetchDiscovery obtains login configuration from inventory.
func (c *CA) FetchDiscovery(ctx context.Context) (*wire.Discovery, error) {
	if c.inventory == nil {
		return nil, fmt.Errorf("inventory service is required")
	}
	return c.inventory.FetchDiscovery(ctx)
}

// RequestPolicy requests policy from the policy server for a cert request.
// The request carries a CA-minted, request-bound JWT (pkg/serviceauth).
func (c *CA) RequestPolicy(ctx context.Context, token string, conn policy.Connection) (*Authorization, error) {
	ctx, cancel := context.WithTimeout(ctx, tlsconfig.DefaultTimeout)
	defer cancel()
	if c.inventory == nil {
		return nil, fmt.Errorf("inventory service is required")
	}
	lookup := inventoryapi.ResolveRequest{Token: token, Host: hostpattern.NormalizeName(conn.RemoteHost)}
	facts, err := c.inventory.Resolve(ctx, lookup)
	if err != nil {
		return nil, fmt.Errorf("resolving inventory: %w", err)
	}
	if err := facts.Validate(lookup.Host); err != nil {
		return nil, err
	}
	body, err := json.Marshal(wire.PolicyRequest{Connection: conn, Facts: facts})
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %w", err)
	}

	if len(body) > wire.MaxBodySize {
		return nil, fmt.Errorf("policy request too large")
	}
	if c.logger != nil {
		c.logger.Debug("http request", "method", "POST", "url", c.policyURL, "body_size", len(body))
	}

	req, err := http.NewRequest("POST", c.policyURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Add("Content-type", "application/json")

	if err := c.svcSigner.Authorize(req, body); err != nil {
		return nil, fmt.Errorf("error signing request: %w", err)
	}

	start := time.Now()
	res, err := c.httpClient.Do(req.WithContext(ctx))
	duration := time.Since(start)
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("http request failed", "method", "POST", "url", c.policyURL, "duration_ms", duration.Milliseconds(), "error", err)
		}
		return nil, fmt.Errorf("error executing request: %w", err)
	}
	defer res.Body.Close()

	if c.logger != nil {
		c.logger.Debug("http response", "method", "POST", "url", c.policyURL, "status", res.StatusCode, "duration_ms", duration.Milliseconds())
	}

	buf, err := io.ReadAll(io.LimitReader(res.Body, wire.MaxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	// Check if policy server response exceeds the limit.
	if len(buf) > wire.MaxBodySize {
		return nil, fmt.Errorf("policy server response exceeds %d bytes", wire.MaxBodySize)
	}

	if res.StatusCode != 200 {
		return nil, &wire.PolicyError{
			StatusCode: res.StatusCode,
			Message:    string(buf),
		}
	}

	policyResp := &wire.PolicyResponse{}
	err = json.Unmarshal(buf, policyResp)
	if err != nil {
		return nil, fmt.Errorf("error parsing response from %s: %w", c.policyURL, err)
	}
	user, host := facts.Directory.User, facts.Inventory.Host
	if user == nil || user.Active == nil || !*user.Active || host == nil {
		return nil, fmt.Errorf("policy issued for absent or inactive inventory records")
	}
	accounts, err := host.Resource.AccountList()
	if err != nil {
		return nil, err
	}
	if conn.RemoteUser == "" || (accounts != nil && !slices.Contains(accounts, conn.RemoteUser)) {
		return nil, fmt.Errorf("policy issued for an account outside the resolved host restrictions")
	}
	expected := conn.RemoteUser
	if host.Principal.Mode == "epithet-principal-v1" {
		expected, err = principal.DeriveV1(principal.Domain(host.Principal.Domain), conn.RemoteUser)
		if err != nil {
			return nil, err
		}
	}
	if policyResp.TTL <= 0 {
		return nil, fmt.Errorf("policy TTL must be positive")
	}
	notAfter := facts.Authentication.ExpiresAt
	if !policyResp.NotAfter.IsZero() && policyResp.NotAfter.Before(notAfter) {
		notAfter = policyResp.NotAfter
	}
	if !notAfter.After(time.Now()) {
		return nil, fmt.Errorf("certificate authorization has expired")
	}
	return &Authorization{
		ID: user.ID, PolicyID: policyResp.PolicyID,
		DirectoryRevision: facts.Directory.Revision, InventoryRevision: facts.Inventory.Revision,
		CertParams: CertParams{
			Identity: user.UserName, Names: []string{expected},
			Expiration: policyResp.TTL, Extensions: policyResp.Extensions, NotAfter: notAfter,
		},
	}, nil
}

// SignPublicKey signs a key to generate a certificate.
func (c *CA) SignPublicKey(rawPubKey sshcert.RawPublicKey, params *CertParams) (sshcert.RawCertificate, error) {
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
		return "", err
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

// WithInventory configures the authentication, discovery, and resolution service.
func WithInventory(endpoint string, cfg tlsconfig.Config) Option {
	return optionFunc(func(c *CA) error {
		client, err := inventoryserver.NewClient(endpoint, c.privateKey, cfg)
		if err != nil {
			return err
		}
		c.inventory = client
		return nil
	})
}
