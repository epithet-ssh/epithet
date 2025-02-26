package agent

import (
	"context"
	"fmt"
	"github.com/epithet-ssh/epithet/pkg/agent/hook"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"net"
	"os"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	log "github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// DefaultTimeout is the default timeout for http calls to the CA
const DefaultTimeout = time.Second * 30

// Agent represents our agent
type Agent struct {
	certExpires *atomic.Uint64
	token       *atomic.String

	keyring  agent.Agent
	caClient *caclient.Client

	authCommand     *hook.Hook
	agentSocketPath string

	publicKey  sshcert.RawPublicKey
	privateKey sshcert.RawPrivateKey

	lock sync.Mutex
}

// Implement agent.Agent and agent.ExtendedAgent

func (a *Agent) Signers() ([]ssh.Signer, error) {
	err := a.EnsureCertificate(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error obtaining certificate: %w", err)
	}
	return a.keyring.Signers()
}

// List returns the identities known to the agent.
func (a *Agent) List() ([]*agent.Key, error) {
	err := a.EnsureCertificate(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error obtaining certificate: %w", err)
	}
	return a.keyring.List()
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	// TODO figure out how to get the right context here
	err := a.EnsureCertificate(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error obtaining certificate: %w", err)
	}

	return a.keyring.Sign(key, data)
}

// Add adds a private key to the agent.
func (a *Agent) Add(key agent.AddedKey) error {
	return a.keyring.Add(key)
}

// Remove removes all identities with the given public key.
func (a *Agent) Remove(key ssh.PublicKey) error {
	return a.keyring.Remove(key)
}

// RemoveAll removes all identities.
func (a *Agent) RemoveAll() error {
	return a.keyring.RemoveAll()
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (a *Agent) Lock(passphrase []byte) error {
	return a.keyring.Lock(passphrase)
}

// Unlock undoes the effect of Lock
func (a *Agent) Unlock(passphrase []byte) error {
	return a.keyring.Unlock(passphrase)
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return a.keyring.(agent.ExtendedAgent).Extension(extensionType, contents)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	err := a.EnsureCertificate(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error obtaining certificate: %w", err)
	}
	return a.keyring.(agent.ExtendedAgent).SignWithFlags(key, data, flags)
}

// End implement agent.Agent and agent.ExtendedAgent

// Create an Agent
func Create(caClient *caclient.Client, agentSocketPath string, authCmd string) (*Agent, error) {
	keyring := agent.NewKeyring()

	pub, priv, err := sshcert.GenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("unable to generate keypair: %w", err)
	}

	a := &Agent{
		privateKey: priv,
		publicKey:  pub,
		keyring:    keyring,

		caClient: caClient,

		certExpires: atomic.NewUint64(0),
		token:       atomic.NewString(""),

		authCommand:     hook.New(authCmd),
		agentSocketPath: agentSocketPath,
	}

	if a.agentSocketPath == "" {
		f, err := os.CreateTemp("", "epithet-agent.*")
		if err != nil {
			return nil, fmt.Errorf("unable to create agent socket: %w", err)
		}
		a.agentSocketPath = f.Name()
		err = f.Close()
		if err != nil {
			return nil, fmt.Errorf("unable to close existing agent socket: %w", err)
		}
		err = os.Remove(f.Name())
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("unable to remove existing agent socket: %w", err)
		}
	}

	return a, nil
}

// Run runs an ssh agent
func Run(ctx context.Context, a *Agent) error {
	err := os.Remove(a.agentSocketPath) //remove socket if it exists
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("unable to remove existing agent socket: %w", err)
	}
	listener, err := net.Listen("unix", a.agentSocketPath)
	if err != nil {
		return fmt.Errorf("unable to listen on %s: %w", a.agentSocketPath, err)
	}

	err = os.Chmod(a.agentSocketPath, 0600)
	if err != nil {
		return fmt.Errorf("unable to set permissions on agent socket: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			err := listener.Close()
			if err != nil {
				log.Debugf("error closing SSH_AUTH_SOCK listener: %v", err)
			}
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				log.Warnf("error on accept from SSH_AUTH_SOCK listener: %v", err)
				continue
			}
			go func() {
				err := agent.ServeAgent(a, conn)
				if err != nil {
					log.Debugf("error serving ssh agent: %v", err)
				}
				err = conn.Close()
				if err != nil {
					log.Debugf("error closing ssh agent connection: %v", err)
				}
			}()
		}
	}
}

// Credential contains the private key and certificate in pem form
type Credential struct {
	PrivateKey  sshcert.RawPrivateKey
	Certificate sshcert.RawCertificate
}

// UseCredential the credentials on the agent
func (a *Agent) UseCredential(c Credential) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	log.Debug("replacing credentials")

	cert, err := sshcert.Parse(c.Certificate)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	privateKey, err := ssh.ParseRawPrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("error parsing private key: %w", err)
	}

	oldKeys, err := a.keyring.List()
	if err != nil {
		return fmt.Errorf("unable to list current credentials: %w", err)
	}
	for _, k := range oldKeys {
		err = a.keyring.Remove(k)
		if err != nil {
			return fmt.Errorf("unable to remove old credential: %w", err)
		}
	}

	err = a.keyring.Add(agent.AddedKey{
		PrivateKey:  privateKey,
		Certificate: cert,
	})
	if err != nil {
		return fmt.Errorf("unable to add new credential: %w", err)
	}
	a.certExpires.Store(uint64(cert.ValidBefore))

	return nil
}

// EnsureCertificate checks if the certificate is expired or invalid
func (a *Agent) EnsureCertificate(ctx context.Context) error {
	if a.certExpires.Load() > uint64(time.Now().Unix())+CertExpirationFuzzWindow {
		// cert expires in the future, short circuit
		return nil
	}

	tries := 0
	for tries < 3 {
		tries++
		// cert is expired, or close to expiration, so refresh it
		credential, tokenExpired, err := a.obtainNewCertificate(ctx, a.authCommand.State())
		if err != nil {
			return fmt.Errorf("error requesting certificate: %w", err)
		}

		switch tokenExpired {
		case ca.StatusOk:
			err = a.UseCredential(*credential)
			if err != nil {
				return fmt.Errorf("error using obtained credential: %w", err)
			}
			return nil
		case ca.StatusNeedToken:
			// obtain a new token and recur
			newToken, err := a.requestNewToken(ctx)
			if err != nil {
				return fmt.Errorf("error requesting new token: %w", err)
			}
			a.token.Store(newToken)
			continue
		case ca.StatusNotAllowed:
			return fmt.Errorf("user not allowed to get certificate")
		case ca.StatusError:
			return fmt.Errorf("unexpected error")
		default:
			panic("unreachable")
		}
	}
	return fmt.Errorf("gave up trying to get new certificate")
}

func (a *Agent) requestNewToken(ctx context.Context) (string, error) {
	err := a.authCommand.Run(map[string]string{})
	if err != nil {
		return "", fmt.Errorf("error requesting new token: %w", err)
	}
	return a.authCommand.State(), nil
}

// obtainNewCertificate tries to convert a `{token, pubkey}` into a certificate
func (a *Agent) obtainNewCertificate(ctx context.Context, token string) (*Credential, ca.Status, error) {
	res, status, err := a.caClient.GetCert(ctx, &caserver.CreateCertRequest{
		PublicKey: a.publicKey,
		Token:     token,
	})
	if err != nil {
		return nil, status, err
	}

	switch status {
	case ca.StatusOk:
		return &Credential{
			PrivateKey:  a.privateKey,
			Certificate: res.Certificate,
		}, status, nil
	case ca.StatusNeedToken, ca.StatusNotAllowed:
		return nil, status, nil
	default:
		return nil, status, fmt.Errorf("unexpected status from server: %d", status)
	}
}

// CertExpirationFuzzWindow is the time, in seconds that we ask for a new
// cert in before the current cert expires.
const CertExpirationFuzzWindow = 20

// TokenSizeLimit is the Authentication token size limit
const TokenSizeLimit = 4094

// AgentSocketPath returns the path for the SSH_AUTH_SOCKET
func (a *Agent) AgentSocketPath() string {
	return a.agentSocketPath
}
