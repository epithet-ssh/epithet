package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/brianm/epithet/pkg/agent"
	"github.com/brianm/epithet/pkg/caclient"
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
	var configs map[string]*config

	if configPath != "" {
		configs, err = loadConfigFile(configPath)
		if err != nil {
			return fmt.Errorf("unable to load config %s: %w", configPath, err)
		}
	} else {
		configs, err = findAndLoadConfig()
		if err != nil {
			return fmt.Errorf("unable to load config: %w", err)
		}
	}

	for name, cfg := range configs {
		caClient := caclient.New(cfg.CA)
		a, err := agent.Start(
			caClient,
			agent.WithAgentSocketPath(cfg.AgentSock),
			agent.WithControlSocketPath(cfg.ControlSock),
			agent.WithHooks(cfg.Hooks),
		)
		if err != nil {
			return fmt.Errorf("unable to start agent %s: %w", name, err)
		}
		log.Infof("started agent [%s] [authn=%s] [agent=%s]", name, a.ControlSocketPath(), a.AgentSocketPath())
		defer a.Close()
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case rs := <-sigs:
		signal.Stop(sigs)
		switch rs {
		case os.Kill:
			log.Info("KILL received")
			syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		default:
			log.Info("INT received")
			return nil
		}
	}
	return nil
}
