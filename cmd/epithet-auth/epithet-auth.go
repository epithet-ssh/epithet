package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	rpc "github.com/brianm/epithet/internal/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var sock = "./control.sock"

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:   "epithet-auth",
	Short: "Submit authentication requests to the agent",
	RunE:  run,
}

func main() {
	cmd.Flags().StringVarP(&sock, "sock", "s", sock, "socket to send to")

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logrus.Debugf("Authenticate success")
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
	logrus.Debugf("invoking Authenticate")
	_, err = client.Authenticate(context.Background(), &rpc.AuthnRequest{
		Token: token,
	})
	return err
}
