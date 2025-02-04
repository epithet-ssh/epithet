package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/naoina/toml"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type unmarshal func([]byte, interface{}) error

func findAndLoadConfig() (*config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error looking for user home (maybe specify config file): %w", err)
	}
	configDir := filepath.Join(home, ".epithet")
	for _, ext := range []string{"toml", "yaml", "yml", "json"} {
		maybe := filepath.Join(configDir, fmt.Sprintf("agent.%s", ext))
		_, err := os.Stat(maybe)
		if err != nil {
			continue
		}
		log.Infof("using config file %s", maybe)
		return loadConfigFile(maybe)
	}

	return nil, errors.New("no config file found")
}

func loadConfigFile(path string) (*config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to load config file: %w", err)
	}

	ext := filepath.Ext(path)
	switch ext {
	case ".yaml":
		return parse(yaml.Unmarshal, body)
	case ".yml":
		return parse(yaml.Unmarshal, body)
	case ".toml":
		return parse(toml.Unmarshal, body)
	case ".json":
		return parse(json.Unmarshal, body)
	default:
		return nil, fmt.Errorf("unknown config file type '%s'", ext)
	}
}

func parse(un unmarshal, body []byte) (*config, error) {
	c := &config{}
	if err := un(body, c); err != nil {
		return nil, err
	}
	err := c.init()
	if err != nil {
		return nil, err
	}

	return c, nil
}

type config struct {
	CA          string `json:"ca_url" yaml:"ca_url" toml:"ca_url"`
	AgentSock   string `json:"ssh_auth_sock" yaml:"ssh_auth_sock" toml:"ssh_auth_sock"`
	AuthCommand string `json:"auth_command" yaml:"auth_command" toml:"auth_command"`
}

func (c *config) init() error {
	if c.AgentSock == "" {
		c.AgentSock = "~/.epithet/ssh_auth.sock"
	}

	_, err := url.Parse(c.CA)
	if err != nil {
		return fmt.Errorf("invalid ca_url: %w", err)
	}

	if c.AuthCommand == "" {
		return errors.New("auth_command must be set")
	}

	return nil
}
