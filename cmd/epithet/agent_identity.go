package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// AgentIdentityCLI authenticates the running agent and reports its identity.
type AgentIdentityCLI struct {
	Broker string `help:"Broker socket path (overrides profile discovery)" short:"b" name:"broker-socket"`
	JSON   bool   `help:"Output in JSON format instead of tab-delimited fields" short:"j"`
}

func (c *AgentIdentityCLI) Run(parent *AgentCLI) error {
	socket, err := resolveAgentBrokerSocket(parent, c.Broker)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return c.run(ctx, socket, os.Stdout, os.Stderr, parent.LoginMethod)
}

func (c *AgentIdentityCLI) run(ctx context.Context, socket string, out, progress io.Writer, loginMethod string) error {
	identity, err := (brokerClient{socket: socket}).identity(ctx, progress, loginMethod)
	if err != nil {
		return err
	}
	if c.JSON {
		return json.NewEncoder(out).Encode(identity)
	}
	return writeAgentIdentity(out, identity)
}

func writeAgentIdentity(out io.Writer, identity *broker.Identity) error {
	var rows strings.Builder
	fmt.Fprintf(&rows, "issuer\t%s\nsubject\t%s\n", identity.Issuer, identity.Subject)
	if identity.OID != "" {
		fmt.Fprintf(&rows, "oid\t%s\n", identity.OID)
	}
	if identity.Email != "" {
		fmt.Fprintf(&rows, "email\t%s\n", identity.Email)
	}
	if identity.EmailVerified != nil {
		fmt.Fprintf(&rows, "email_verified\t%t\n", *identity.EmailVerified)
	}
	_, err := io.WriteString(out, rows.String())
	return err
}

// makeAgentIdentityVerifier uses the running agent's discovery configuration.
// OIDC discovery happens on demand; starting an agent does not require login.
func makeAgentIdentityVerifier(auth wire.AuthConfig, tlsCfg tlsconfig.Config) broker.IdentityVerifier {
	var mu sync.Mutex
	var cached *oidc.Verifier
	getValidator := func(ctx context.Context) (*oidc.Verifier, error) {
		mu.Lock()
		defer mu.Unlock()
		if cached != nil {
			return cached, nil
		}
		v, err := oidc.NewVerifier(ctx, oidc.VerifierConfig{
			IssuerURL: auth.Issuer, ClientID: auth.ClientID,
			TLSConfig: tlsCfg,
		})
		if err == nil {
			cached = v // Reuse the HTTP connection pool and signing-key cache.
		}
		return v, err // Failed discovery is retried by the next request.
	}
	return func(ctx context.Context, token string) (*broker.Identity, error) {
		validator, err := getValidator(ctx)
		if err != nil {
			return nil, err
		}
		claims, err := validator.Verify(ctx, token)
		if err != nil {
			return nil, err
		}
		var raw map[string]any
		if err := claims.Claims(&raw); err != nil {
			return nil, fmt.Errorf("decoding OIDC claims: %w", err)
		}
		identity := &broker.Identity{Issuer: auth.Issuer, Subject: claims.Subject}
		identity.OID, _ = raw["oid"].(string)
		identity.Email, _ = raw["email"].(string)
		if verified, ok := raw["email_verified"].(bool); ok {
			identity.EmailVerified = &verified
		}
		return identity, nil
	}
}
