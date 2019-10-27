package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/brianm/epithet/pkg/ca"
	"github.com/brianm/epithet/pkg/caserver"
	"github.com/brianm/epithet/pkg/sshcert"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var verbosity = 0
var configPath string
var address string = ":12510"

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:              "epithet-ca",
	Short:            "Run the epithet ca server",
	PersistentPreRun: logging,
	RunE:             run,
}

func main() {
	cmd.Flags().CountVarP(&verbosity, "verbose", "v", "how verbose to be, can use multiple")
	cmd.Flags().StringVarP(&configPath, "config", "F", "CONFIG_FILE", "config file to use")
	cmd.Flags().StringVarP(&address, "address", "a", address, "address to bind to, ie :12510")

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cc *cobra.Command, args []string) error {
	var err error
	var cfg *config
	if configPath != "" {
		cfg, err = loadConfigFile(configPath)
		if err != nil {
			return err
		}
	} else {
		cfg, err = findAndLoadConfig()
		if err != nil {
			return err
		}
	}

	privKey, err := ioutil.ReadFile(cfg.PrivKey)
	if err != nil {
		return fmt.Errorf("unable to load private key %s: %w", cfg.PrivKey, err)
	}

	pubKey, err := ioutil.ReadFile(cfg.PubKey)
	if err != nil {
		return fmt.Errorf("unable to load public key %s: %v", cfg.PubKey, err)
	}

	c, err := ca.New(sshcert.RawPublicKey(string(pubKey)), sshcert.RawPrivateKey(string(privKey)))
	if err != nil {
		return fmt.Errorf("unable to create CA: %w", err)
	}

	handler := caserver.New(c)

	log.Infof("starting ca at %s", address)
	err = http.ListenAndServe(address, handler)
	if err != nil {
		return err
	}

	return nil
}

func logging(cmd *cobra.Command, args []string) {
	log.SetOutput(os.Stdout)
	switch verbosity {
	case 0:
		log.SetLevel(log.WarnLevel)
	case 1:
		log.SetLevel(log.InfoLevel)
	default: // 2+
		log.SetLevel(log.DebugLevel)
	}
}
