package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
)

type InventoryTokenCLI struct {
	Create InventoryTokenCreateCLI `cmd:"create" help:"Create a reusable enrollment token"`
}

type InventoryTokenCreateCLI struct {
	Subject   string        `required:"true" help:"Provisioning principal recorded in enrollment audit"`
	ExpiresIn time.Duration `name:"expires-in" required:"true" help:"Explicit lifetime of at least 1s (for example 2160h)"`
	Quiet     bool          `help:"Print only the token value"`
}

func (c *InventoryTokenCreateCLI) Run(p *InventoryCLI) error {
	if c.Subject == "" || c.ExpiresIn < time.Second {
		return fmt.Errorf("subject and expires-in of at least 1s are required")
	}
	r, err := p.request(facts.ControlRequest{Action: "token-create", Subject: c.Subject, LifetimeSeconds: int64(c.ExpiresIn / time.Second)})
	if err != nil {
		return err
	}
	if c.Quiet {
		fmt.Println(r.Token.Token)
		return nil
	}
	if r.CAURL == "" {
		fmt.Printf("Token %s expires %s\n", r.Token.Token, r.Token.ExpiresAt.Format(time.RFC3339))
		return nil
	}
	fmt.Printf("Token %s expires %s\n\nepithet host enroll --ca %s --token %s\n", r.Token.Token, r.Token.ExpiresAt.Format(time.RFC3339), shellQuote(r.CAURL), shellQuote(r.Token.Token))
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
