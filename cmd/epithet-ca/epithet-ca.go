package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
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

	privKey, err := os.ReadFile(cfg.PrivKey)
	if err != nil {
		return fmt.Errorf("unable to load private key %s: %w", cfg.PrivKey, err)
	}

	c, err := ca.New(
		sshcert.RawPrivateKey(string(privKey)),
		cfg.PolicyURL)
	if err != nil {
		return fmt.Errorf("unable to create CA: %w", err)
	}

	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Handle("/", caserver.New(c))

	log.Infof("starting ca at %s", address)
	err = http.ListenAndServe(address, r)
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
