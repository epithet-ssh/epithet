package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/inventory"
	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
	"gopkg.in/yaml.v3"
)

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
		return nil, fmt.Errorf("static record: edit the inventory.static YAML configuration and restart inventory")
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
		return fmt.Errorf("static record: edit inventory.static configuration and restart inventory")
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
	r, err := p.request(inventoryapi.ControlRequest{Action: "token-create", LifetimeSeconds: int64(c.ExpiresIn / time.Second)})
	if err != nil {
		return err
	}
	if c.Quiet {
		fmt.Println(r.Token.ID)
		return nil
	}
	fmt.Printf("Token %s expires %s\n\nepithet host enroll --ca-url %s --token %s\n", r.Token.ID, r.Token.ExpiresAt.Format(time.RFC3339), shellQuote(r.CAURL), shellQuote(r.Token.ID))
	return nil
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

type InventoryTokenListCLI struct{}

func (*InventoryTokenListCLI) Run(p *InventoryCLI) error {
	r, err := p.request(inventoryapi.ControlRequest{Action: "token-list"})
	if err != nil {
		return err
	}
	return printInventory(r.Tokens)
}

type InventoryTokenRevokeCLI struct {
	ID string `arg:""`
}

func (c *InventoryTokenRevokeCLI) Run(p *InventoryCLI) error {
	_, err := p.request(inventoryapi.ControlRequest{Action: "token-revoke", ID: c.ID})
	return err
}

var errCanceled = errors.New("canceled")

func readChoice(input *bufio.Reader, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := input.ReadString('\n')
	if err == io.EOF {
		return "exit", nil
	}
	return strings.ToLower(strings.TrimSpace(line)), err
}
func editProposal(initial inventory.Proposal, input *bufio.Reader, validators ...func(inventory.Proposal) error) (inventory.Proposal, error) {
	data, err := yaml.Marshal(initial)
	if err != nil {
		return initial, err
	}
	f, err := os.CreateTemp("", "epithet-host-*.yaml")
	if err != nil {
		return initial, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return initial, err
	}
	if err = f.Close(); err != nil {
		return initial, err
	}
	for {
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vi"
		}
		var command *exec.Cmd
		if runtime.GOOS == "windows" {
			command = exec.Command("cmd.exe", "/C", editor+" \""+f.Name()+"\"")
		} else {
			command = exec.Command("/bin/sh", "-c", "exec "+editor+" \"$1\"", "epithet-editor", f.Name())
		}
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err = command.Run(); err != nil {
			return initial, fmt.Errorf("editor exited unsuccessfully; no submission: %w", err)
		}
		data, err = os.ReadFile(f.Name())
		if err != nil {
			return initial, err
		}
		if len(bytesTrim(data)) == 0 {
			return initial, errCanceled
		}
		proposal, validation := inventory.ParseProposal(data)
		if validation == nil {
			for _, validate := range validators {
				if validation = validate(proposal); validation != nil {
					break
				}
			}
		}
		if validation != nil {
			fmt.Fprintln(os.Stderr, "Invalid host YAML:", validation)
			choice, e := readChoice(input, "edit / [cancel: default on Enter]: ")
			if e != nil {
				return initial, e
			}
			if choice == "e" || choice == "edit" {
				continue
			}
			return initial, errCanceled
		}
		return proposal, nil
	}
}
func bytesTrim(data []byte) []byte { return []byte(strings.TrimSpace(string(data))) }
