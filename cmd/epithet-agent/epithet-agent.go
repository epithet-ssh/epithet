package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var verbosity = 0
var configPath string

// AgentCommand is an agent command
var cmd = &cobra.Command{
	Use:              "epithet-agent",
	Short:            "Run the epithet ssh agent",
	PersistentPreRun: logging,
	RunE:             run,
}

func main() {
	cmd.Flags().CountVarP(&verbosity, "verbose", "v", "how verbose to be, can use multiple")
	cmd.Flags().StringVarP(&configPath, "config", "F", "CONFIG_FILE", "config file to use")
	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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

func run(cc *cobra.Command, args []string) error {
	var err error
	var cfg *config

	if configPath != "" {
		cfg, err = loadConfigFile(configPath)
		if err != nil {
			return fmt.Errorf("unable to load config %s: %w", configPath, err)
		}
	} else {
		cfg, err = findAndLoadConfig()
		if err != nil {
			return fmt.Errorf("unable to load config: %w", err)
		}
	}

	caClient := caclient.New(cfg.CA)
	a, err := agent.Start(
		context.Background(),
		caClient,
		cfg.AuthCommand,
		agent.WithAgentSocketPath(cfg.AgentSock),
		agent.WithAuthCommand(cfg.AuthCommand),
	)
	if err != nil {
		return fmt.Errorf("unable to start agent: %w", err)
	}
	log.Infof("started agent at [%s]", a.AgentSocketPath())
	defer a.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	signal.Stop(sigs)
	log.Info("INT received")
	return nil
}
