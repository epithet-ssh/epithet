package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"

	"github.com/naoina/toml"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type unmarshal func([]byte, interface{}) error

func findAndLoadConfig() (map[string]*config, error) {
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

func loadConfigFile(path string) (map[string]*config, error) {
	body, err := ioutil.ReadFile(path)
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

func parse(un unmarshal, body []byte) (map[string]*config, error) {
	agents := map[string]*config{}

	if err := un(body, &agents); err != nil {
		return nil, err
	}

	for name, cfg := range agents {
		err := cfg.init(name)
		if err != nil {
			return nil, err
		}
	}

	return agents, nil
}

type config struct {
	CA        string `json:"ca_url" yaml:"ca_url" toml:"ca_url"`
	AgentSock string `json:"agent_sock" yaml:"agent_sock" toml:"agent_sock"`
	AuthnSock string `json:"authn_sock" yaml:"authn_sock" toml:"authn_sock"`
	Name      string
}

func (c *config) init(name string) error {
	c.Name = name

	if c.AgentSock == "" {
		c.AgentSock = fmt.Sprintf("~/.epithet/%s.agent.sock", name)
	}

	if c.AuthnSock == "" {
		c.AuthnSock = fmt.Sprintf("~/.epithet/%s.authn.sock", name)
	}

	_, err := url.Parse(c.CA)
	if err != nil {
		return fmt.Errorf("invalid ca_url: %w", err)
	}
	return nil
}
