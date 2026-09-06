package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	authoidc "github.com/epithet-ssh/epithet/pkg/auth/oidc"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

// IdentityCLI obtains a verified identity without requesting a certificate or
// requiring an inventory binding. It also works against a pre-migration CA.
type IdentityCLI struct {
	CAURL []string `name:"ca-url" short:"c" help:"CA URL (repeatable; defaults to agent.ca-url from client config)"`
}

func (c *IdentityCLI) Run(tlsCfg tlsconfig.Config) error {
	paths, err := config.ExpandGlobs(defaultConfigPatterns)
	if err != nil {
		return err
	}
	urls, err := c.resolveCAURLs(paths, string(cli.Config))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return c.run(ctx, urls, tlsCfg, os.Stdout, os.Stderr)
}

// Kong resolves only the selected command's flags. Resolve the existing agent
// CA setting separately, using the same loader, default files, and explicit
// --config overlay as the main parser. This preserves scalar/list handling and
// per-flag precedence without maintaining another YAML interpretation.
func (c *IdentityCLI) resolveCAURLs(defaultPaths []string, explicitConfig string) ([]string, error) {
	if len(c.CAURL) > 0 {
		return c.CAURL, nil
	}
	var inherited struct {
		Config kong.ConfigFlag `name:"config"`
		Agent  struct {
			CAURL []string `name:"ca-url"`
		} `cmd:"agent"`
	}
	parser, err := kong.New(&inherited, kong.Configuration(kongyaml.Loader, defaultPaths...))
	if err != nil {
		return nil, err
	}
	args := []string{"agent"}
	if explicitConfig != "" {
		args = append([]string{"--config", explicitConfig}, args...)
	}
	if _, err := parser.Parse(args); err != nil {
		return nil, fmt.Errorf("reading agent CA configuration: %w", err)
	}
	if len(inherited.Agent.CAURL) == 0 {
		return nil, fmt.Errorf("no CA URL configured; set agent.ca-url in your client config or pass --ca-url")
	}
	return inherited.Agent.CAURL, nil
}

func (c *IdentityCLI) run(ctx context.Context, urls []string, tlsCfg tlsconfig.Config, out, progress io.Writer) error {
	endpoints, err := caclient.ParseCAURLs(urls)
	if err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		if err := tlsCfg.ValidateURL(endpoint.URL); err != nil {
			return err
		}
	}
	client, err := caclient.New(endpoints, caclient.WithTLSConfig(tlsCfg))
	if err != nil {
		return err
	}
	discovery, err := client.GetDiscovery(ctx)
	if err != nil {
		return fmt.Errorf("fetching authentication configuration: %w", err)
	}
	if discovery.Auth == nil {
		return fmt.Errorf("CA discovery has no authentication configuration")
	}
	auth := discovery.Auth
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer: auth.Issuer, ClientID: auth.ClientID, TLSConfig: tlsCfg,
	})
	if err != nil {
		return err
	}
	token, _, err := authoidc.Authenticate(ctx, authoidc.Config{
		IssuerURL: auth.Issuer, ClientID: auth.ClientID,
		ClientSecret: auth.ClientSecret, TLSConfig: tlsCfg,
	}, nil, progress)
	if err != nil {
		return err
	}
	return writeVerifiedIdentity(ctx, validator, token, out)
}

// Never print or persist the bearer token, refresh token, or client secret.
func writeVerifiedIdentity(ctx context.Context, validator *oidc.Validator, token string, out io.Writer) error {
	claims, err := validator.Validate(ctx, token)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
	}{Issuer: claims.Issuer, Subject: claims.Subject})
}
