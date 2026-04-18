package agent

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const agentSuccess = 6

// ExtensionHandler handles a single epithet protocol extension.
// contents is the raw request payload; returns raw response payload (without the type byte).
type ExtensionHandler func(contents []byte) ([]byte, error)

// ProxyAgent wraps an upstream ssh agent, proxying standard operations and
// dispatching epithet protocol extensions to registered handlers.
// Unregistered extensions are forwarded to the upstream agent.
type ProxyAgent struct {
	upstream   agent.ExtendedAgent
	extensions map[string]ExtensionHandler
}

// NewProxyAgent creates a ProxyAgent that proxies to the given upstream agent.
func NewProxyAgent(upstream agent.ExtendedAgent) *ProxyAgent {
	return &ProxyAgent{
		upstream:   upstream,
		extensions: make(map[string]ExtensionHandler),
	}
}

// RegisterExtension registers a handler for the given extension type.
func (p *ProxyAgent) RegisterExtension(name string, handler ExtensionHandler) {
	p.extensions[name] = handler
}

// Extension dispatches to a registered handler or forwards to upstream.
func (p *ProxyAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if handler, ok := p.extensions[extensionType]; ok {
		payload, err := handler(contents)
		if err != nil {
			return nil, err
		}
		// Prepend SSH_AGENT_SUCCESS byte — ServeAgent sends this as-is,
		// and the client strips the type byte before returning.
		return append([]byte{agentSuccess}, payload...), nil
	}
	return p.upstream.Extension(extensionType, contents)
}

// Standard agent methods — all delegate to upstream.

func (p *ProxyAgent) List() ([]*agent.Key, error) {
	return p.upstream.List()
}

func (p *ProxyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return p.upstream.Sign(key, data)
}

func (p *ProxyAgent) Add(key agent.AddedKey) error {
	return p.upstream.Add(key)
}

func (p *ProxyAgent) Remove(key ssh.PublicKey) error {
	return p.upstream.Remove(key)
}

func (p *ProxyAgent) RemoveAll() error {
	return p.upstream.RemoveAll()
}

func (p *ProxyAgent) Lock(passphrase []byte) error {
	return p.upstream.Lock(passphrase)
}

func (p *ProxyAgent) Unlock(passphrase []byte) error {
	return p.upstream.Unlock(passphrase)
}

func (p *ProxyAgent) Signers() ([]ssh.Signer, error) {
	return p.upstream.Signers()
}

func (p *ProxyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return p.upstream.SignWithFlags(key, data, flags)
}
