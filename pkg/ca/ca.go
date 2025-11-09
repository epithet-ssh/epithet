package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	rekor "github.com/sigstore/rekor/pkg/pki/ssh"
	"golang.org/x/crypto/ssh"
)

// PolicyError represents an error from the policy server.
// The CA server should return the same status code to the client.
type PolicyError struct {
	StatusCode int
	Message    string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("policy server returned %d: %s", e.StatusCode, e.Message)
}

// CA performs CA operations
type CA struct {
	signer     ssh.Signer
	privateKey sshcert.RawPrivateKey
	policyURL  string
	httpClient *http.Client
}

// get the URL of the Policy Server
func (c *CA) PolicyURL() string {
	return c.policyURL
}

// New creates a new CA
func New(privateKey sshcert.RawPrivateKey, policyURL string, options ...Option) (*CA, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}
	ca := &CA{
		signer:     signer,
		privateKey: privateKey,
		policyURL:  policyURL,
	}

	for _, o := range options {
		o.apply(ca)
	}

	if ca.httpClient == nil {
		ca.httpClient = &http.Client{
			Timeout: time.Second * 30,
		}
	}

	return ca, nil
}

// Option configures the agent
type Option interface {
	apply(*CA)
}

type optionFunc func(*CA)

func (f optionFunc) apply(a *CA) {
	f(a)
}

// WithHTTPClient configures the CA to use the specified HTTP Client
func WithHTTPClient(httpClient *http.Client) Option {
	return optionFunc(func(c *CA) {
		c.httpClient = httpClient
	})
}

// PublicKey returns the ssh on-disk format public key for the CA
func (c *CA) PublicKey() sshcert.RawPublicKey {
	pk := c.signer.PublicKey()
	return sshcert.RawPublicKey(string(ssh.MarshalAuthorizedKey(pk)))
}

// CertParams are options which can be set on a certificate
type CertParams struct {
	Identity   string            `json:"identity"`
	Names      []string          `json:"principals"`
	Expiration time.Duration     `json:"expiration"`
	Extensions map[string]string `json:"extensions"`
}

// PolicyResponse is the response from the policy server, containing both
// the certificate parameters and the policy
type PolicyResponse struct {
	CertParams CertParams    `json:"certParams"`
	Policy     policy.Policy `json:"policy"`
}

func Verify(pubkey sshcert.RawPublicKey, token, signature string) error {
	s, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("error decoding signature: %w", err)
	}

	return rekor.Verify(bytes.NewReader([]byte(token)), s, []byte(pubkey))
}

func (c *CA) Sign(value string) (signature string, err error) {
	sig, err := rekor.Sign(string(c.privateKey), bytes.NewReader([]byte(value)))
	if err != nil {
		return "", fmt.Errorf("error signing value: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

// RequestPolicy requests policy from the policy url
func (c *CA) RequestPolicy(ctx context.Context, token string, conn policy.Connection) (*PolicyResponse, error) {
	sig, err := c.Sign(token)
	if err != nil {
		return nil, fmt.Errorf("error creating signed nonce: %w", err)
	}

	body, err := json.Marshal(&map[string]interface{}{
		"token":      token,
		"signature":  sig,
		"connection": conn,
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing input: %w", err)
	}
	req, err := http.NewRequest("POST", c.policyURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("Content-type", "application/json")

	res, err := c.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("error executing request: %w", err)
	}
	defer res.Body.Close()

	lim := io.LimitReader(res.Body, 8196)
	buf, err := io.ReadAll(lim)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	// Check HTTP status code
	if res.StatusCode != 200 {
		// Policy server returned an error - wrap it to signal to CA server
		// CA server should return the same status code to the client
		return nil, &PolicyError{
			StatusCode: res.StatusCode,
			Message:    string(buf),
		}
	}

	policyResp := &PolicyResponse{}
	err = json.Unmarshal(buf, policyResp)
	if err != nil {
		return nil, fmt.Errorf("error parsing response from %s: %w", c.policyURL, err)
	}
	return policyResp, nil
}

// SignPublicKey signs a key to generate a certificate
func (c *CA) SignPublicKey(rawPubKey sshcert.RawPublicKey, params *CertParams) (sshcert.RawCertificate, error) {
	// `ssh-keygen -s test/ca/ca -z 2 -V +15m -I brianm -n brianm,waffle ./id_ed25519.pub`
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

	certificate := ssh.Certificate{
		Serial:          serial,
		Key:             pubKey,
		KeyId:           params.Identity,
		ValidPrincipals: params.Names,
		ValidAfter:      uint64(time.Now().Unix() - 60),
		ValidBefore:     uint64(time.Now().Add(params.Expiration).Unix()),
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

// AuthToken is the token passed from the plugin through to
// the CA (and to the ca verifier plugin matching Provider)
// Token is opaque and can hold whatever the plugins need it to
type AuthToken struct {
	Provider string
	Token    string
}
