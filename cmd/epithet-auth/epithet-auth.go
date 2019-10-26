package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/spf13/cobra"
)

var sock = ""

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:   "epithet-ca",
	Short: "Run the epithet ca server",
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
	in, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(in)
	if err != nil {
		return err
	}

	return nil
}
