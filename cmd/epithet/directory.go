package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/epithet-ssh/epithet/pkg/inventoryapi"
)

type DirectoryCLI struct {
	ManagementCLI `embed:""`
	Users         DirectoryUsersCLI  `cmd:"users" help:"Inspect users in the selected directory"`
	Groups        DirectoryGroupsCLI `cmd:"groups" help:"Inspect and manage SCIM group policy bindings"`
}

type DirectoryUsersCLI struct {
	List DirectoryUsersListCLI `cmd:"list" default:"withargs" help:"List user identities, active status, and policy groups"`
}

type DirectoryUsersListCLI struct {
	JSON bool `help:"Print the complete user snapshot as JSON"`
}

func (c *DirectoryUsersListCLI) Run(p *DirectoryCLI) error {
	r, err := p.request(inventoryapi.ControlRequest{Action: "directory-users"})
	if err != nil {
		return err
	}
	if r.DirectoryUsers == nil {
		return fmt.Errorf("inventory omitted directory users")
	}
	return c.writeOutput(os.Stdout, r.DirectoryUsers)
}

func (c *DirectoryUsersListCLI) writeOutput(w io.Writer, snapshot *inventoryapi.UserSnapshot) error {
	if c.JSON {
		return json.NewEncoder(w).Encode(snapshot)
	}
	if _, err := fmt.Fprintln(w, "USERNAME\tID\tACTIVE\tGROUPS"); err != nil {
		return err
	}
	for _, u := range snapshot.Users {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%t\t%s\n", directoryColumn(u.UserName), directoryColumn(u.ID), u.Active, directoryColumn(strings.Join(u.Groups, ","))); err != nil {
			return err
		}
	}
	return nil
}

// Minimal management uses the existing agent-authenticated inventory transport.
// Rebinding explicitly names the target ID and the revision previously reviewed.
type DirectoryGroupsCLI struct {
	List  DirectoryGroupsListCLI  `cmd:"list" default:"withargs" help:"List directory groups, policy aliases, and conflicts"`
	Bind  DirectoryGroupsBindCLI  `cmd:"bind" help:"Assign or explicitly rebind a policy alias to a SCIM group"`
	Audit DirectoryGroupsAuditCLI `cmd:"audit" help:"Show a page of directory mutation and binding audit"`
}
type DirectoryGroupsListCLI struct {
	JSON bool `help:"Print the complete binding snapshot as JSON"`
}

func (c *DirectoryGroupsListCLI) Run(p *DirectoryCLI) error {
	r, err := p.request(inventoryapi.ControlRequest{Action: "directory-groups"})
	if err != nil {
		return err
	}
	if r.Directory == nil {
		return fmt.Errorf("inventory omitted directory snapshot")
	}
	if c.JSON {
		return json.NewEncoder(os.Stdout).Encode(r.Directory)
	}
	fmt.Printf("REVISION\tID\tSTATUS\tPOLICY_NAME\tDIRECTORY_NAME\n")
	for _, g := range r.Directory.Groups {
		fmt.Printf("%d\t%s\t%s\t%s\t%s\n", r.Directory.Revision, g.ID, g.Status, directoryColumn(g.Alias), directoryColumn(g.DisplayName))
	}
	return nil
}

type DirectoryGroupsBindCLI struct {
	Alias    string `arg:"" help:"Policy name to bind"`
	GroupID  string `arg:"" help:"Full SCIM group resource ID"`
	Revision uint64 `required:"true" help:"Directory revision shown by groups list"`
}

func (c *DirectoryGroupsBindCLI) Run(p *DirectoryCLI) error {
	_, err := p.request(inventoryapi.ControlRequest{Action: "directory-bind", Alias: c.Alias, ID: c.GroupID, Revision: c.Revision})
	return err
}

type DirectoryGroupsAuditCLI struct {
	After uint64 `help:"Return events after this audit sequence"`
	Limit int    `help:"Maximum events to return (1-1000; default 100)"`
}

func (c *DirectoryGroupsAuditCLI) Run(p *DirectoryCLI) error {
	r, err := p.request(inventoryapi.ControlRequest{Action: "directory-audit", AuditAfter: c.After, AuditLimit: c.Limit})
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
