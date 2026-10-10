package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/facts"
)

type InventoryTokenCLI struct {
	Create InventoryTokenCreateCLI `cmd:"create" help:"Create an expiring single-use preapproval token"`
	List   InventoryTokenListCLI   `cmd:"list" help:"List token IDs, expiration, and redemption state"`
	Revoke InventoryTokenRevokeCLI `cmd:"revoke" help:"Revoke an unused token"`
}

type InventoryTokenCreateCLI struct {
	ExpiresIn time.Duration `name:"expires-in" default:"1h" help:"Lifetime (maximum 24h)"`
	Quiet     bool          `help:"Print only the token value"`
}

func (c *InventoryTokenCreateCLI) Run(p *InventoryCLI) error {
	if c.ExpiresIn < time.Second || c.ExpiresIn > 24*time.Hour {
		return fmt.Errorf("expires-in must be between 1s and 24h")
	}
	r, err := p.request(facts.ControlRequest{Action: "token-create", LifetimeSeconds: int64(c.ExpiresIn / time.Second)})
	if err != nil {
		return err
	}
	if c.Quiet {
		fmt.Println(r.Token.ID)
		return nil
	}
	fmt.Printf("Token %s expires %s\n\nepithet host enroll --ca %s --token %s\n", r.Token.ID, r.Token.ExpiresAt.Format(time.RFC3339), shellQuote(r.CAURL), shellQuote(r.Token.ID))
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

type InventoryTokenListCLI struct {
	After string `help:"Return tokens after this full token ID"`
	Limit int    `help:"Maximum tokens to return (1-1000; default 100)"`
}

func (c *InventoryTokenListCLI) Run(p *InventoryCLI) error {
	r, err := p.request(facts.ControlRequest{Action: "token-list", After: c.After, Limit: c.Limit})
	if err != nil {
		return err
	}
	return printInventory(r.Tokens)
}

type InventoryTokenRevokeCLI struct {
	ID string `arg:""`
}

func (c *InventoryTokenRevokeCLI) Run(p *InventoryCLI) error {
	_, err := p.request(facts.ControlRequest{Action: "token-revoke", ID: c.ID})
	return err
}
