package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"gopkg.in/yaml.v3"
)

type InventoryCLI struct {
	ManagementCLI  `embed:""`
	ControlURL     string `help:"Public control management URL for token-authenticated automation" name:"control-url"`
	AdminTokenFile string `help:"Inventory automation bearer token file" name:"admin-token-file"`
	tlsConfig      tlsconfig.Config

	StateDir string              `help:"Shared root for inventory/ and directory/ storage (default: native system state directory)" name:"state-dir"`
	Serve    InventoryServeCLI   `cmd:"" default:"withargs" help:"Serve managed inventory"`
	List     InventoryListCLI    `cmd:"list" aliases:"l,ls" help:"List managed host records"`
	Add      InventoryAddCLI     `cmd:"add" help:"Add a managed host in EDITOR"`
	Show     InventoryShowCLI    `cmd:"show" aliases:"s,sh" help:"Show one host record"`
	Edit     InventoryEditCLI    `cmd:"edit" aliases:"e,ed" help:"Edit a managed host in EDITOR"`
	Approve  InventoryApproveCLI `cmd:"approve" aliases:"a,app" help:"Review, edit, approve, or deny enrollment"`
	Remove   InventoryRemoveCLI  `cmd:"remove" aliases:"rm" help:"Withdraw a managed host from inventory"`
	Token    InventoryTokenCLI   `cmd:"token" help:"Create or revoke enrollment tokens"`
	Audit    InventoryAuditCLI   `cmd:"audit" help:"Show durable inventory mutation audit"`

	Listen        string `help:"Address to listen on" short:"l" default:"127.0.0.1:9998"`
	ControlPubkey string `help:"Control service public key for administration" name:"control-public-key"`
	CAPubkey      string `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-public-key"`
	Check         bool   `help:"Validate the inventory database, then exit" name:"check"`
}

func printInventory(v any) error {
	// Preserve the API field names when presenting records as YAML.
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var public any
	if err = yaml.Unmarshal(data, &public); err != nil {
		return err
	}
	data, err = yaml.Marshal(public)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

func (c *InventoryCLI) find(id string) (*facts.HostRecord, error) {
	// Full IDs use the server's record index rather than downloading every host.
	_, hexErr := hex.DecodeString(id)
	if len(id) == 64 && hexErr == nil {
		response, err := c.request(facts.ControlRequest{Action: "get", ID: id})
		if err != nil {
			return nil, err
		}
		if response.Host == nil {
			return nil, inventory.ErrNotFound
		}
		return response.Host, nil
	}

	var match *facts.HostRecord
	after := ""
	for {
		resp, err := c.request(facts.ControlRequest{Action: "list", After: after, Limit: inventory.DefaultPageLimit})
		if err != nil {
			return nil, err
		}
		for _, h := range resp.Hosts {
			matches := strings.HasPrefix(h.ID, id)
			for _, n := range h.Host.Names {
				matches = matches || n == id
			}
			if matches {
				if match != nil {
					return nil, fmt.Errorf("ambiguous host; use the full record ID")
				}
				copy := h
				match = &copy
			}
		}
		if len(resp.Hosts) < inventory.DefaultPageLimit {
			break
		}
		next := resp.Hosts[len(resp.Hosts)-1].ID
		if next <= after {
			return nil, fmt.Errorf("inventory pagination did not advance")
		}
		after = next
	}
	if match != nil {
		// List records have no ETag. Read the selected record before review.
		response, err := c.request(facts.ControlRequest{Action: "get", ID: match.ID})
		if err != nil {
			return nil, err
		}
		if response.Host == nil {
			return nil, inventory.ErrNotFound
		}
		return response.Host, nil
	}
	return nil, inventory.ErrNotFound
}

type InventoryListCLI struct {
	After   string `help:"Return records after this full record ID"`
	Limit   int    `help:"Maximum records to return (1-1000; default 100)"`
	Pending bool   `help:"Show only pending requests"`
}

func (c *InventoryListCLI) Run(p *InventoryCLI) error {
	r, err := p.request(facts.ControlRequest{Action: "list", After: c.After, Limit: c.Limit, Pending: c.Pending})
	if err != nil {
		return err
	}
	next := ""
	if len(r.Hosts) > 0 {
		next = r.Hosts[len(r.Hosts)-1].ID
	}
	displayNames := func(h facts.HostRecord) string {
		return strings.Join(h.Host.Names, ", ")
	}
	slices.SortStableFunc(r.Hosts, func(a, b facts.HostRecord) int {
		return strings.Compare(displayNames(a), displayNames(b))
	})
	if _, err := fmt.Fprintln(os.Stdout, "ID\tSTATUS\tNAMES"); err != nil {
		return err
	}
	for _, h := range r.Hosts {
		id := h.ID
		if len(id) == 64 {
			id = id[:12]
		}
		if _, err := fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", id, h.Status, displayNames(h)); err != nil {
			return err
		}
	}
	limit := c.Limit
	if limit == 0 {
		limit = inventory.DefaultPageLimit
	}
	if len(r.Hosts) == limit {
		fmt.Fprintf(os.Stderr, "Continue with --after %s\n", next)
	}
	return nil
}

type InventoryShowCLI struct {
	Host string `arg:"" help:"Host record ID or unambiguous name"`
}

type InventoryAddCLI struct {
	Names []string `arg:"" help:"Hostnames or wildcard names (quote shell wildcards)"`
}

func (c *InventoryAddCLI) Run(p *InventoryCLI) error {
	fmt.Fprintln(os.Stderr, "Set realm to the shared SSH authorization boundary for these names, and choose its labels and accounts.")
	host, err := editInventory(inventory.Host{
		Names: c.Names, Labels: map[string]string{}, Accounts: []string{}, PrincipalMode: inventory.EpithetPrincipalV1,
	}, bufio.NewReader(os.Stdin), inventory.ParseHost)
	if errors.Is(err, errCanceled) {
		return nil
	}
	if err != nil {
		return err
	}
	submitted := controlHost(host)
	r, err := p.request(facts.ControlRequest{Action: "add", Host: &submitted})
	if err != nil {
		return err
	}
	return printInventory(r.Host)
}

func (c *InventoryShowCLI) Run(p *InventoryCLI) error {
	h, err := p.find(c.Host)
	if err != nil {
		return err
	}
	return printInventory(h)
}

type InventoryEditCLI struct {
	Host string `arg:""`
}

func (c *InventoryEditCLI) Run(p *InventoryCLI) error {
	h, err := p.find(c.Host)
	if err != nil {
		return err
	}
	h, err = editInventoryHost(p, h, bufio.NewReader(os.Stdin))
	if errors.Is(err, errCanceled) {
		return nil
	}
	if err != nil {
		return err
	}
	return printInventory(h)
}

func editInventoryHost(p *InventoryCLI, h *facts.HostRecord, input *bufio.Reader) (*facts.HostRecord, error) {
	host, err := editInventory(hostFromControl(h.Host), input, inventory.ParseHost)
	if err != nil {
		return nil, err
	}
	submitted := controlHost(host)
	r, err := p.request(facts.ControlRequest{Action: "edit", ID: h.ID, ExpectedVersion: h.Version, Host: &submitted})
	if err != nil {
		return nil, err
	}
	return r.Host, nil
}

type InventoryApproveCLI struct {
	Host string `arg:""`
}

func (c *InventoryApproveCLI) Run(p *InventoryCLI) error {
	h, err := p.find(c.Host)
	if err != nil {
		return err
	}
	if h.Status != inventory.StatusPending {
		return fmt.Errorf("only pending requests can be reviewed")
	}
	input := bufio.NewReader(os.Stdin)
	for {
		if err = printInventory(h); err != nil {
			return err
		}
		choice, err := readChoice(input, "approve / edit / deny / [exit: default on Enter]: ")
		if err != nil {
			return err
		}
		switch choice {
		case "", "x", "exit":
			return nil
		case "e", "edit":
			updated, e := editInventoryHost(p, h, input)
			if errors.Is(e, errCanceled) {
				continue
			}
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
				continue
			}
			h = updated
		case "a", "approve", "d", "deny":
			action := "approve"
			if choice == "d" || choice == "deny" {
				action = "deny"
			}
			r, e := p.request(facts.ControlRequest{Action: action, ID: h.ID, ExpectedVersion: h.Version})
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
				fresh, e2 := p.find(h.ID)
				if e2 != nil {
					return e2
				}
				h = fresh
				if h.Status != inventory.StatusPending {
					return fmt.Errorf("request is now %s", h.Status)
				}
				continue
			}
			return printInventory(r.Host)
		default:
			fmt.Fprintln(os.Stderr, "Choose approve, edit, deny, or exit.")
		}
	}
}

type InventoryRemoveCLI struct {
	Host string `arg:""`
}

func (c *InventoryRemoveCLI) Run(p *InventoryCLI) error {
	h, err := p.find(c.Host)
	if err != nil {
		return err
	}

	_, err = p.request(facts.ControlRequest{Action: "remove", ID: h.ID, ExpectedVersion: h.Version})
	return err
}

type InventoryAuditCLI struct {
	Cursor string `help:"Continue from the cursor returned by the previous audit page"`
	Limit  int    `help:"Maximum events to return (1-1000; default 100)"`
}

func (c *InventoryAuditCLI) Run(p *InventoryCLI) error {
	r, err := p.request(facts.ControlRequest{Action: "audit", AuditCursor: c.Cursor, AuditLimit: c.Limit})
	if err != nil {
		return err
	}
	return printInventory(r.Audit)
}

func (c *InventoryCLI) BeforeRun(cfg tlsconfig.Config) error { c.tlsConfig = cfg; return nil }
func (c *InventoryCLI) request(req facts.ControlRequest) (*broker.InventoryResponse, error) {
	if c.ControlURL == "" && c.AdminTokenFile == "" {
		return c.ManagementCLI.request(req)
	}
	if c.ControlURL == "" || c.AdminTokenFile == "" {
		return nil, fmt.Errorf("automation requires both --control-url and --admin-token-file")
	}
	token, err := readBearerToken("", c.AdminTokenFile, "inventory")
	if err != nil {
		return nil, err
	}
	client, err := facts.NewAdminClient(c.ControlURL, c.tlsConfig)
	if err != nil {
		return nil, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	result, _, err := client.Control(ctx, token, req)
	if err != nil {
		return nil, err
	}
	return &broker.InventoryResponse{ControlResponse: *result}, nil
}
