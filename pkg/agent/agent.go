package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
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

var errAgentStopped error = errors.New("agent has been stopped")

// DefaultTimeout is the default timeout for http calls to the CA
const DefaultTimeout = time.Second * 30

// Agent represents our agent
type Agent struct {
	running     *atomic.Bool
	certExpires *atomic.Uint64
	lastToken   *atomic.String

	keyring  agent.Agent
	caClient *caclient.Client
	ctx      context.Context

	agentSocketPath string
	agentListener   net.Listener

	publicKey  sshcert.RawPublicKey
	privateKey sshcert.RawPrivateKey

	authCommand string
	lock        sync.Mutex
}

// Implement agent.Agent and agent.ExtendedAgent

func (a *Agent) Signers() ([]ssh.Signer, error) {
	//TODO implement me
	panic("implement me")
}

// List returns the identities known to the agent.
func (a *Agent) List() ([]*agent.Key, error) {
	return a.keyring.List()
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	// TODO check if cert has expired
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
	// TODO check if cert has expired
	return a.keyring.(agent.ExtendedAgent).SignWithFlags(key, data, flags)
}

// End implement agent.Agent and agent.ExtendedAgent

// Start creates and starts an SSH Agent
func Start(ctx context.Context, caClient *caclient.Client, agentSocketPath string, authCmd string) (*Agent, error) {
	keyring := agent.NewKeyring()
	if ctx == nil {
		ctx = context.Background()
	}
	a := &Agent{
		keyring:         keyring,
		caClient:        caClient,
		running:         atomic.NewBool(true),
		certExpires:     atomic.NewUint64(0),
		lastToken:       atomic.NewString(""),
		authCommand:     authCmd,
		agentSocketPath: agentSocketPath,
		ctx:             ctx,
	}

	pub, priv, err := sshcert.GenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("unable to generate keypair: %w", err)
	}
	a.privateKey = priv
	a.publicKey = pub

	if a.agentSocketPath == "" {
		f, err := os.CreateTemp("", "epithet-agent.*")
		if err != nil {
			a.Close()
			return nil, fmt.Errorf("unable to create agent socket: %w", err)
		}
		a.agentSocketPath = f.Name()
		err = f.Close()
		if err != nil {
			a.Close()
			return nil, fmt.Errorf("unable to close existing agent socket: %w", err)
		}
		err = os.Remove(f.Name())
		if err != nil && !os.IsNotExist(err) {
			a.Close()
			return nil, fmt.Errorf("unable to remove existing agent socket: %w", err)
		}
	}

	err = os.Remove(a.agentSocketPath) //remove socket if it exists
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to remove existing agent socket: %w", err)
	}
	agentListener, err := net.Listen("unix", a.agentSocketPath)
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("unable to listen on %s: %w", a.agentSocketPath, err)
	}

	err = os.Chmod(a.agentSocketPath, 0600)
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("unable to set permissions on agent socket: %w", err)
	}
	a.agentListener = agentListener
	go a.listenAndServeAgent(agentListener)

	return a, nil
}

// Credential contains the private key and certificate in pem form
type Credential struct {
	PrivateKey  sshcert.RawPrivateKey
	Certificate sshcert.RawCertificate
}

// UseCredential the credentials on the agemnt
func (a *Agent) UseCredential(c Credential) error {
	if !a.Running() {
		return errAgentStopped
	}

	log.Debug("replacing credentials")
	oldKeys, err := a.keyring.List()
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to list current credentials: %w", err)
	}

	cert, err := sshcert.Parse(c.Certificate)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	priv, err := ssh.ParseRawPrivateKey([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("error parsing private key: %w", err)
	}
	err = a.keyring.Add(agent.AddedKey{
		PrivateKey:  priv,
		Certificate: cert,
	})
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to add new credential: %w", err)
	}

	for _, k := range oldKeys {
		err = a.keyring.Remove(k)
		if err != nil {
			a.Close()
			return fmt.Errorf("Unable to remove old credential: %w", err)
		}
	}

	a.certExpires.Store(uint64(cert.ValidBefore))

	return nil
}

// EnsureCertificate checks if the certificate is expired or invalid
func (a *Agent) EnsureCertificate(ctx context.Context) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.certExpires.Load() < uint64(time.Now().Unix())+CertExpirationFuzzWindow {
		// cert is expired, or close to expiration, so refresh it
		err := a.RequestCertificate(ctx, a.lastToken.Load())
		if err != nil {
			return fmt.Errorf("error requesting certificate: %w", err)
		}
	}
	return nil
}

// RequestCertificate tries to convert a `{token, pubkey}` into a certificate
func (a *Agent) RequestCertificate(ctx context.Context, token string) error {
	a.lastToken.Store(token)

	res, err := a.caClient.GetCert(ctx, &caserver.CreateCertRequest{
		PublicKey: a.publicKey,
		Token:     token,
	})

	if err != nil {
		return err
	}

	err = a.UseCredential(Credential{
		PrivateKey:  a.privateKey,
		Certificate: res.Certificate,
	})
	if err != nil {
		return err
	}
	return nil
}

func (a *Agent) listenAndServeAgent(listener net.Listener) {
	for a.running.Load() {
		conn, err := listener.Accept()
		if err != nil {
			// nothing we can do on this loop
			if conn != nil {
				conn.Close()
			}
			if !a.running.Load() {
				// we are shutting down, just return
				return
			}
			log.Warnf("error on accept from SSH_AUTH_SOCK listener: %v", err)
		}
		go a.serveAgent(conn)
	}
}

// CertExpirationFuzzWindow is the time, in seconds that we ask for a new
// cert in before the current cert expires.
const CertExpirationFuzzWindow = 20

func (a *Agent) serveAgent(conn net.Conn) {
	log.Debug("new connection to agent")
	// close the connection after the credential is served
	defer conn.Close()

	err := a.EnsureCertificate(a.ctx)
	if err != nil {
		log.Warnf("error obtaining certificate: %v", err)
		return
	}

	err = agent.ServeAgent(a, conn)
	if err != nil && err != io.EOF {
		log.Warnf("error from ssh-agent: %v", err)
	}
}

// TokenSizeLimit is the Authentication token size limit
const TokenSizeLimit = 4094

// AgentSocketPath returns the path for the SSH_AUTH_SOCKET
func (a *Agent) AgentSocketPath() string {
	return a.agentSocketPath
}

// IsAgentStopped lets you test if an error indicates that the agent has been stopped
func IsAgentStopped(err error) bool {
	return errors.Is(err, errAgentStopped)
}

// Running reports on whether the current agent is healthy
func (a *Agent) Running() bool {
	return a.running.Load()
}

// Close stops the agent and cleansup after it
func (a *Agent) Close() {
	a.running.Store(false)
	if a.agentListener != nil {
		_ = a.agentListener.Close() //ignore error
	}
}
