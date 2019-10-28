package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/brianm/epithet/pkg/sshcert"
	"golang.org/x/crypto/ssh"
)

// CA performs CA operations
type CA struct {
	publicKey  sshcert.RawPublicKey
	signer     ssh.Signer
	policyURL  string
	httpClient *http.Client
}

// New creates a new CA
func New(publicKey sshcert.RawPublicKey, privateKey sshcert.RawPrivateKey, policyURL string, options ...Option) (*CA, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, err
	}
	ca := &CA{
		signer:    signer,
		publicKey: publicKey,
		policyURL: policyURL,
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
	return c.publicKey
}

// CertParams are options which can be set on a certificate
type CertParams struct {
	Identity   string
	Names      []string
	Expiration time.Duration
	Extensions []string
}

// RequestPolicy requests policy from the policy url
func (c *CA) RequestPolicy(ctx context.Context, token string) (*CertParams, error) {
	body, err := json.Marshal(&map[string]string{
		"token": token,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.policyURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-type", "application/json")

	res, err := c.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	lim := io.LimitReader(res.Body, 8196)
	buf, err := ioutil.ReadAll(lim)
	if err != nil {
		return nil, err
	}
	params := &CertParams{}
	err = json.Unmarshal(buf, params)
	return params, nil
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
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
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
