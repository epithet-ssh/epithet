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

const DEFAULT_ADDRESS = "0.0.0.0:${PORT}"
const DEFAULT_POLICY = "${POLICY_URL}"

var address string = DEFAULT_ADDRESS
var caPrivateKeyPath = "/etc/epithet/ca.key"
var policyURL string = DEFAULT_POLICY

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:              "epithet-ca",
	Short:            "Run the epithet ca server",
	PersistentPreRun: logging,
	RunE:             run,
}

func main() {
	cmd.Flags().CountVarP(&verbosity, "verbose", "v", "how verbose to be, can use multiple")
	cmd.Flags().StringVarP(&policyURL, "policy", "p", policyURL, "URL for policy service")
	cmd.Flags().StringVarP(&caPrivateKeyPath, "key", "k", caPrivateKeyPath, "path to ca private key")
	cmd.Flags().StringVarP(&address, "address", "a", address, "address to bind to, ie :12510")

	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cc *cobra.Command, args []string) error {
	var err error

	privKey, err := os.ReadFile(caPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("unable to load ca key: %w", err)
	}

	if policyURL == DEFAULT_POLICY {
		policyURL = os.Getenv("POLICY_URL")
	}

	c, err := ca.New(
		sshcert.RawPrivateKey(string(privKey)),
		policyURL)
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

	if address == DEFAULT_ADDRESS {
		address = fmt.Sprintf("0.0.0.0:%s", os.Getenv("PORT"))
	}

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
