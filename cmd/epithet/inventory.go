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

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
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

func (c *InventoryCLI) find(id string) (*inventoryapi.HostRecord, error) {
	// Full IDs use the server's record index rather than downloading every host.
	_, hexErr := hex.DecodeString(id)
	if len(id) == 64 && hexErr == nil {
		response, err := c.request(inventoryapi.ControlRequest{Action: "get", ID: id})
		if err != nil {
			return nil, err
		}
		if response.Host == nil {
			return nil, inventory.ErrNotFound
		}
		return response.Host, nil
	}

	resp, err := c.request(inventoryapi.ControlRequest{Action: "list"})
	if err != nil {
		return nil, err
	}
	var matches []inventoryapi.HostRecord
	for _, h := range resp.Hosts {
		if h.ID == id {
			return &h, nil
		}
		match := strings.HasPrefix(h.ID, id) || h.Proposal.Pattern == id
		for _, n := range h.Proposal.Names {
			match = match || n == id
		}
		if match {
			matches = append(matches, h)
		}
	}
	if len(matches) == 1 {
		return &matches[0], nil
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("ambiguous host; use the full record ID")
	}
	return nil, inventory.ErrNotFound
}

type InventoryListCLI struct {
	Pending bool `help:"Show only pending requests"`
}

func (c *InventoryListCLI) Run(p *InventoryCLI) error {
	r, err := p.request(inventoryapi.ControlRequest{Action: "list"})
	if err != nil {
		return err
	}
	displayNames := func(h inventoryapi.HostRecord) string {
		if h.Proposal.Pattern != "" {
			return h.Proposal.Pattern
		}
		return strings.Join(h.Proposal.Names, ", ")
	}
	slices.SortStableFunc(r.Hosts, func(a, b inventoryapi.HostRecord) int {
		return strings.Compare(displayNames(a), displayNames(b))
	})
	if _, err := fmt.Fprintln(os.Stdout, "ID\tSTATUS\tNAMES"); err != nil {
		return err
	}
	for _, h := range r.Hosts {
		if c.Pending && h.Status != "pending" {
			continue
		}
		id := h.ID
		if len(id) == 64 {
			id = id[:12]
		}
		if _, err := fmt.Fprintf(os.Stdout, "%s\t%s\t%s\n", id, h.Status, displayNames(h)); err != nil {
			return err
		}
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
	r, err := p.request(inventoryapi.ControlRequest{Action: "add-pattern", Host: &submitted})
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

func editInventoryHost(p *InventoryCLI, h *inventoryapi.HostRecord, input *bufio.Reader) (*inventoryapi.HostRecord, error) {
	proposal, err := editProposal(inventory.ProposalFromControl(h.Proposal), input)
	if err != nil {
		return nil, err
	}
	submitted := proposal.ControlProposal()
	r, err := p.request(inventoryapi.ControlRequest{Action: "edit", ID: h.ID, Revision: h.Revision, Host: &submitted})
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
			r, e := p.request(inventoryapi.ControlRequest{Action: action, ID: h.ID, Revision: h.Revision})
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

	_, err = p.request(inventoryapi.ControlRequest{Action: "remove", ID: h.ID, Revision: h.Revision})
	return err
}

type InventoryAuditCLI struct{}

func (*InventoryAuditCLI) Run(p *InventoryCLI) error {
	r, err := p.request(inventoryapi.ControlRequest{Action: "audit"})
	if err != nil {
		return err
	}
	return printInventory(r.Audit)
}
