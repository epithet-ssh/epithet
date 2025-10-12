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

	lock sync.Mutex
}

// Start creates and starts an SSH Agent
func Start(ctx context.Context, caClient *caclient.Client, agentSocketPath string) (*Agent, error) {
	keyring := agent.NewKeyring()
	a := &Agent{
		ctx:             ctx,
		agentSocketPath: agentSocketPath,
		keyring:         keyring,
		caClient:        caClient,
		running:         atomic.NewBool(true),
		certExpires:     atomic.NewUint64(0),
		lastToken:       atomic.NewString(""),
	}

	pub, priv, err := sshcert.GenerateKeys()
	if err != nil {
		return nil, err
	}
	a.privateKey = priv
	a.publicKey = pub

	if a.ctx == nil {
		a.ctx = context.Background()
	}

	err = a.startAgentListener()
	if err != nil {
		return nil, err
	}
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

// CheckCertificate checks if the certificate is expired or invalid
func (a *Agent) CheckCertificate() bool {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a.certExpires.Load() < uint64(time.Now().Unix())+CertExpirationFuzzWindow
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

func (a *Agent) startAgentListener() error {
	if a.agentSocketPath == "" {
		f, err := os.CreateTemp("", "epithet-agent.*")
		if err != nil {
			a.Close()
			return fmt.Errorf("unable to create agent socket: %w", err)
		}
		a.agentSocketPath = f.Name()
		f.Close()
		os.Remove(f.Name())
	}

	os.Remove(a.agentSocketPath) //remove socket if it exists
	agentListener, err := net.Listen("unix", a.agentSocketPath)
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to listen on %s: %w", a.agentSocketPath, err)
	}

	err = os.Chmod(a.agentSocketPath, 0600)
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to set permissions on agent socket: %w", err)
	}
	a.agentListener = agentListener
	go a.listenAndServeAgent(agentListener)
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

	err := agent.ServeAgent(a.keyring, conn)
	if err != nil && err != io.EOF {
		log.Warnf("error from ssh-agent: %v", err)
	}
	// close the connection after the credential is served
	conn.Close()
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
