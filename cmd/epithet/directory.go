package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/epithet-ssh/epithet/pkg/facts"
)

type DirectoryCLI struct {
	Serve               DirectoryServeCLI `cmd:"" default:"withargs" help:"Serve directory facts and private administration"`
	Mode                string            `help:"Directory mode: static files or SCIM provisioning" default:"static" enum:"static,scim" name:"directory-mode"`
	Static              []string          `help:"Static directory files or globs" name:"directory-static-file"`
	StateDir            string            `help:"Root for directory storage" name:"state-dir"`
	SCIMUserIDAttribute string            `help:"SCIM string attribute used to assign user IDs on creation; must match the configured OIDC identity" name:"scim-user-id-attribute" default:"externalId"`
	Listen              string            `help:"Private directory listener" default:"127.0.0.1:9997"`
	CAPubkey            string            `help:"CA public key for fact reads" name:"ca-public-key"`
	ControlPubkey       string            `help:"Control public key for administration" name:"control-public-key"`
	Check               bool              `help:"Validate directory configuration and storage"`

	ManagementCLI `embed:""`
	Users         DirectoryUsersCLI  `cmd:"users" aliases:"u" help:"Inspect users in the selected directory"`
	Groups        DirectoryGroupsCLI `cmd:"groups" aliases:"g" help:"Inspect SCIM groups and directory audit"`
}

type DirectoryUsersCLI struct {
	List DirectoryUsersListCLI `cmd:"list" aliases:"l,ls" default:"withargs" help:"List SCIM users"`
}

type DirectoryUsersListCLI struct {
	JSON bool `help:"Print one SCIM user resource per line as JSON"`
}

func (c *DirectoryUsersListCLI) Run(p *DirectoryCLI) error {
	return runDirectoryList(p, "Users", c.JSON)
}

func runDirectoryList(p *DirectoryCLI, resource string, jsonOutput bool) error {
	socket, err := resolveAgentBrokerSocket(&AgentCLI{Name: p.Name}, p.Broker)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return listDirectory(ctx, brokerClient{socket: socket}, resource, jsonOutput, os.Stdout, os.Stderr)
}

// listDirectory emits each page before fetching the next. Offset pagination is a view of
// each page's current state, not a snapshot held across the entire enumeration.
func listDirectory(ctx context.Context, client brokerClient, resource string, jsonOutput bool, out, progress io.Writer) error {
	for start := 1; ; {
		page, err := client.directoryPage(ctx, resource, start, progress)
		if err != nil {
			return err
		}
		if page.StartIndex != start {
			return fmt.Errorf("agent returned an unexpected SCIM startIndex")
		}
		if start == 1 && !jsonOutput {
			header := "USERNAME\tID\tEXTERNAL_ID\tACTIVE"
			if resource == "Groups" {
				header = "ID\tNAME"
			}
			if _, err := fmt.Fprintln(out, header); err != nil {
				return err
			}
		}
		if err := writeDirectoryPage(out, page, resource, jsonOutput); err != nil {
			return err
		}
		if len(page.Resources) == 0 {
			return nil
		}
		if len(page.Resources) > int(^uint(0)>>1)-start {
			return fmt.Errorf("SCIM startIndex overflow")
		}
		start += len(page.Resources)
		if start > page.TotalResults {
			return nil
		}
	}
}

func writeDirectoryPage(out io.Writer, page *facts.SCIMPage, kind string, jsonOutput bool) error {
	for _, resource := range page.Resources {
		if jsonOutput {
			if err := json.NewEncoder(out).Encode(resource); err != nil {
				return err
			}
			continue
		}
		if kind == "Groups" {
			var group struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
			}
			if err := json.Unmarshal(resource, &group); err != nil {
				return fmt.Errorf("invalid SCIM group: %w", err)
			}
			if _, err := fmt.Fprintf(out, "%s\t%s\n", directoryColumn(group.ID), directoryColumn(group.DisplayName)); err != nil {
				return err
			}
			continue
		}
		var user struct {
			UserName   string `json:"userName"`
			ID         string `json:"id"`
			ExternalID string `json:"externalId"`
			Active     *bool  `json:"active"`
		}
		if err := json.Unmarshal(resource, &user); err != nil {
			return fmt.Errorf("invalid SCIM user: %w", err)
		}
		active := ""
		if user.Active != nil {
			active = strconv.FormatBool(*user.Active)
		}
		if _, err := fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", directoryColumn(user.UserName), directoryColumn(user.ID), directoryColumn(user.ExternalID), active); err != nil {
			return err
		}
	}
	return nil
}

type DirectoryGroupsCLI struct {
	List  DirectoryGroupsListCLI  `cmd:"list" aliases:"l,ls" default:"withargs" help:"List current directory group names and IDs"`
	Audit DirectoryGroupsAuditCLI `cmd:"audit" help:"Show a page of directory audit"`
}
type DirectoryGroupsListCLI struct {
	JSON bool `help:"Print one SCIM group resource per line as JSON"`
}

func (c *DirectoryGroupsListCLI) Run(p *DirectoryCLI) error {
	return runDirectoryList(p, "Groups", c.JSON)
}

type DirectoryGroupsAuditCLI struct {
	Cursor string `help:"Continue from the cursor returned by the previous audit page"`
	Limit  int    `help:"Maximum events to return (1-1000; default 100)"`
}

func (c *DirectoryGroupsAuditCLI) Run(p *DirectoryCLI) error {
	r, err := p.request(facts.ControlRequest{Action: "directory-audit", AuditCursor: c.Cursor, AuditLimit: c.Limit})
	if err != nil {
		return err
	}
	return printInventory(r.DirectoryAudit)
}

// Provisioned names must not inject terminal controls or extra table rows.
func directoryColumn(s string) string {
	if strings.IndexFunc(s, unicode.IsControl) >= 0 || strings.Contains(s, "\\") {
		return strconv.Quote(s)
	}
	return s
}
