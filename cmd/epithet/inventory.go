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

	InventoryMode string              `help:"Host inventory mode: static files only, or enrollment with optional static files" name:"inventory-mode" default:"enrollment" enum:"static,enrollment"`
	StateDir      string              `help:"Shared root for inventory/ and directory/ storage (default: native system state directory)" name:"state-dir"`
	Serve         InventoryServeCLI   `cmd:"" default:"withargs" help:"Serve directory and inventory"`
	List          InventoryListCLI    `cmd:"list" aliases:"l,li,lis" help:"List static and dynamic host records"`
	Show          InventoryShowCLI    `cmd:"show" aliases:"s,sh,show" help:"Show one host record"`
	Edit          InventoryEditCLI    `cmd:"edit" aliases:"e,ed,edi" help:"Edit a dynamic host in EDITOR"`
	Approve       InventoryApproveCLI `cmd:"approve" aliases:"a,ap,app" help:"Review, edit, approve, or deny enrollment"`
	Remove        InventoryRemoveCLI  `cmd:"remove" help:"Withdraw a dynamic host from inventory"`
	Token         InventoryTokenCLI   `cmd:"token" help:"Create, list, or revoke enrollment tokens"`
	Audit         InventoryAuditCLI   `cmd:"audit" help:"Show durable inventory mutation audit"`

	Listen        string   `help:"Address to listen on" short:"l" default:"127.0.0.1:9998"`
	ControlPubkey string   `help:"Control service public key for administration" name:"control-public-key"`
	CAPubkey      string   `help:"CA public key (URL, file path, or literal SSH key)" name:"ca-public-key"`
	Static        []string `help:"Static inventory file path or glob (repeatable; optional in enrollment mode)" name:"inventory-static-file"`
	PrincipalMode string   `help:"Default host principal mode" name:"principal-mode" default:"epithet-principal-v1" enum:"account-name,epithet-principal-v1"`
	Check         bool     `help:"Validate inventory files, then exit" name:"check"`
}

func printInventory(v any) error {
	// Preserve the API field names and source metadata when presenting records as YAML.
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
	if (len(id) == 64 && hexErr == nil) || strings.HasPrefix(id, "static:") {
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
		match := strings.HasPrefix(h.ID, id)
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
		if h.Pattern != "" {
			return h.Pattern
		}
		return strings.Join(h.Proposal.Names, ", ")
	}
	slices.SortStableFunc(r.Hosts, func(a, b inventoryapi.HostRecord) int {
		return strings.Compare(displayNames(a), displayNames(b))
	})
	if _, err := fmt.Fprintln(os.Stdout, "ID\tSTATUS\tSOURCE\tNAMES"); err != nil {
		return err
	}
	for _, h := range r.Hosts {
		if c.Pending && h.Status != "pending" {
			continue
		}
		id := h.ID
		if len(id) == 64 && h.Source != "static" {
			id = id[:12]
		}
		if _, err := fmt.Fprintf(os.Stdout, "%s\t%s\t%s\t%s\n", id, h.Status, h.Source, displayNames(h)); err != nil {
			return err
		}
	}
	return nil
}

type InventoryShowCLI struct {
	Host string `arg:"" help:"Host record ID or unambiguous name"`
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
	if h.Source == "static" || strings.HasPrefix(h.ID, "static:") {
		return nil, fmt.Errorf("static record: edit the YAML files selected by inventory-static-file and restart inventory")
	}
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
	if h.Source == "static" {
		return fmt.Errorf("static record: edit the YAML files selected by inventory-static-file and restart inventory")
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
