package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/brianm/epithet/pkg/caclient"
	"github.com/brianm/epithet/pkg/caserver"
	"github.com/brianm/epithet/pkg/sshcert"
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
	running *atomic.Bool

	keyring  agent.Agent
	caClient *caclient.Client
	ctx      context.Context

	agentSocketPath string
	agentListener   net.Listener

	authnSocketPath string
	authnListener   net.Listener

	publicKey  sshcert.RawPublicKey
	privateKey sshcert.RawPrivateKey
}

// Start creates and starts an SSH Agent
func Start(caClient *caclient.Client, options ...Option) (*Agent, error) {
	keyring := agent.NewKeyring()
	a := &Agent{
		keyring:  keyring,
		running:  atomic.NewBool(true),
		caClient: caClient,
	}

	for _, o := range options {
		o.apply(a)
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

	if a.agentSocketPath == "" {
		f, err := ioutil.TempFile("", "epithet-agent.*")
		if err != nil {
			a.Close()
			return nil, fmt.Errorf("unable to create agent socket: %w", err)
		}
		a.agentSocketPath = f.Name()
		f.Close()
		os.Remove(f.Name())
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

	// todo add authnListener
	if a.authnSocketPath == "" {
		f, err := ioutil.TempFile("", "epithet-authn.*")
		if err != nil {
			a.Close()
			return nil, fmt.Errorf("unable to create authn socket: %w", err)
		}
		a.authnSocketPath = f.Name()
		f.Close()
		os.Remove(f.Name())
	}

	authnListener, err := net.Listen("unix", a.authnSocketPath)
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("unable to listen on %s: %w", a.authnSocketPath, err)
	}

	err = os.Chmod(a.authnSocketPath, 0600)
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("unable to set permissions on authn socket: %w", err)
	}
	a.authnListener = authnListener
	go a.listenAndServeAuthn(authnListener)

	return a, nil
}

// Option configures the agent
type Option interface {
	apply(*Agent) error
}

type optionFunc func(*Agent) error

func (f optionFunc) apply(a *Agent) error {
	return f(a)
}

// WithAgentSocketPath specifies the SSH_AUTH_SOCK path to create
func WithAgentSocketPath(path string) Option {
	return optionFunc(func(a *Agent) error {
		a.agentSocketPath = path
		return nil
	})
}

// WithAuthenticationSocketPath specifies the SSH_AUTH_SOCK path to create
func WithAuthenticationSocketPath(path string) Option {
	return optionFunc(func(a *Agent) error {
		a.authnSocketPath = path
		return nil
	})
}

// WithContext specifies a context.Context that agent will use
// and which can be cancelled, triggering the agent to stop.
// This context will also be used for outgoing requests to the
// CA
func WithContext(ctx context.Context) Option {
	return optionFunc(func(a *Agent) error {
		go func() {
			select {
			case <-ctx.Done():
				a.Close()
			}
		}()
		return nil
	})
}

// AgentSocketPath returns the path for the SSH_AUTH_SOCKET
func (a *Agent) AgentSocketPath() string {
	return a.agentSocketPath
}

// AuthnSocketPath returns the path for the SSH_AUTH_SOCKET
func (a *Agent) AuthnSocketPath() string {
	return a.authnSocketPath
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
func (a *Agent) Close() error {
	a.running.Store(false)
	_ = a.agentListener.Close() //ignore error

	return nil
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

	return nil
}

func (a *Agent) listenAndServeAuthn(listener net.Listener) {
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
			log.Warnf("error on accept from authn listener: %v", err)
		}
		go func() {
			defer conn.Close()
			err := a.serveAuthn(conn)
			if err != nil {
				log.Warnf("error serving authn connection: %v", err)
			}
		}()
	}
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
		go func() {
			err := agent.ServeAgent(a.keyring, conn)
			if err != nil && err != io.EOF {
				log.Warnf("error from ssh-agent: %v", err)
				_ = conn.Close()
				// ignoring close erros
			}
		}()
	}
}

// TokenSizeLimit is the Authentication token size limit
const TokenSizeLimit = 4094

func (a *Agent) serveAuthn(conn net.Conn) error {
	defer conn.Close()
	rdr := io.LimitReader(conn, TokenSizeLimit)
	token, err := ioutil.ReadAll(rdr)
	if err != nil {
		return err
	}

	r, err := a.caClient.GetCert(a.ctx, &caserver.CreateCertRequest{
		PublicKey: a.publicKey,
		Token:     string(token),
	})
	if err != nil {
		return err
	}

	err = a.UseCredential(Credential{
		PrivateKey:  a.privateKey,
		Certificate: r.Certificate,
	})
	if err != nil {
		return err
	}

	return nil
}
