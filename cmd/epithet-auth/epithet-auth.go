package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	rpc "github.com/brianm/epithet/internal/agent"
	"github.com/spf13/cobra"
)

var sock = ""

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:   "epithet-auth",
	Short: "Submit authentication requests to the agent",
	RunE:  run,
}

func main() {
	cmd.Flags().StringVarP(&sock, "sock", "s", "./authn.sock", "socket to send to")

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cc *cobra.Command, args []string) error {
	var token string
	if len(args) != 0 {
		token = strings.Join(args, " ")
	} else {
		in, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		token = string(in)
	}

	client, err := rpc.NewClient(sock)
	if err != nil {
		return err
	}

	_, err = client.Authenticate(context.Background(), &rpc.AuthnRequest{
		Token: token,
	})
	return err
}
