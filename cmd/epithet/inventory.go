package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/epithet-ssh/epithet/pkg/facts/inventory"
	"gopkg.in/yaml.v3"
)

type InventoryCLI struct {
	ManagementCLI `embed:""`

	StateDir   string                 `help:"Shared root for inventory/ and directory/ storage (default: native system state directory)" name:"state-dir"`
	Serve      InventoryServeCLI      `cmd:"" default:"withargs" help:"Serve managed inventory"`
	List       InventoryListCLI       `cmd:"list" aliases:"l,ls" help:"List managed host records"`
	AddPattern InventoryAddPatternCLI `cmd:"add-pattern" help:"Declare a managed hostname pattern in EDITOR"`
	Show       InventoryShowCLI       `cmd:"show" aliases:"s,sh" help:"Show one host record"`
	Edit       InventoryEditCLI       `cmd:"edit" aliases:"e,ed" help:"Edit a managed host in EDITOR"`
	Approve    InventoryApproveCLI    `cmd:"approve" aliases:"a,app" help:"Review, edit, approve, or deny enrollment"`
	Remove     InventoryRemoveCLI     `cmd:"remove" aliases:"rm" help:"Withdraw a managed host from inventory"`
	Token      InventoryTokenCLI      `cmd:"token" help:"Create, list, or revoke enrollment tokens"`
	Audit      InventoryAuditCLI      `cmd:"audit" help:"Show durable inventory mutation audit"`

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
			matches := strings.HasPrefix(h.ID, id) || h.Proposal.Pattern == id
			for _, n := range h.Proposal.Names {
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
		return match, nil
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
		if h.Proposal.Pattern != "" {
			return h.Proposal.Pattern
		}
		return strings.Join(h.Proposal.Names, ", ")
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

type InventoryAddPatternCLI struct {
	Pattern string `arg:"" help:"Hostname pattern (quote shell wildcards)"`
}

func (c *InventoryAddPatternCLI) Run(p *InventoryCLI) error {
	fmt.Fprintln(os.Stderr, "Set realm to the shared SSH authorization boundary for this pattern, and choose its labels and accounts.")
	proposal, err := editProposal(inventory.Proposal{
		Pattern: c.Pattern, Labels: map[string]string{}, Accounts: []string{},
		PrincipalMode: inventory.EpithetPrincipalV1,
	}, bufio.NewReader(os.Stdin), func(p inventory.Proposal) error {
		if p.Pattern == "" {
			return fmt.Errorf("pattern is required")
		}
		return nil
	})
	if errors.Is(err, errCanceled) {
		return nil
	}
	if err != nil {
		return err
	}
	submitted := proposal.ControlProposal()
	r, err := p.request(facts.ControlRequest{Action: "add-pattern", Host: &submitted})
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
	proposal, err := editProposal(inventory.ProposalFromControl(h.Proposal), input)
	if err != nil {
		return nil, err
	}
	submitted := proposal.ControlProposal()
	r, err := p.request(facts.ControlRequest{Action: "edit", ID: h.ID, Revision: h.Revision, Host: &submitted})
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
	if h.Status != "pending" {
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
			r, e := p.request(facts.ControlRequest{Action: action, ID: h.ID, Revision: h.Revision})
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
				fresh, e2 := p.find(h.ID)
				if e2 != nil {
					return e2
				}
				h = fresh
				if h.Status != "pending" {
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

	_, err = p.request(facts.ControlRequest{Action: "remove", ID: h.ID, Revision: h.Revision})
	return err
}

type InventoryAuditCLI struct {
	After uint64 `help:"Return events after this audit sequence"`
	Limit int    `help:"Maximum events to return (1-1000; default 100)"`
}

func (c *InventoryAuditCLI) Run(p *InventoryCLI) error {
	r, err := p.request(facts.ControlRequest{Action: "audit", AuditAfter: c.After, AuditLimit: c.Limit})
	if err != nil {
		return err
	}
	return printInventory(r.Audit)
}
