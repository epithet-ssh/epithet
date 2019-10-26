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

const configBase = "/etc/epithet"

func findAndLoadConfig() (*config, error) {
	for _, ext := range []string{"toml", "yaml", "yml", "json"} {
		maybe := filepath.Join(configBase, fmt.Sprintf("%s/ca.%s", configBase, ext))
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

func parse(un unmarshal, body []byte) (*config, error) {
	cfg := config{}

	if err := un(body, &cfg); err != nil {
		return nil, err
	}

	cfg.init()

	return &cfg, nil
}

type config struct {
	PolicyURL string `json:"policy_url" yaml:"policy_url" toml:"policy_url"`
	PubKey    string `json:"public_key" yaml:"public_key" toml:"public_key"`
	PrivKey   string `json:"private_key" yaml:"private_key" toml:"private_key"`
	Name      string
}

func (c *config) init() error {

	if c.PubKey == "" {
		c.PubKey = fmt.Sprintf("%s/cakey.pub", configBase)
	}

	if c.PrivKey == "" {
		c.PrivKey = fmt.Sprintf("%s/cakey", configBase)
	}

	_, err := url.Parse(c.PolicyURL)
	if err != nil {
		return fmt.Errorf("invalid policy_url: %w", err)
	}

	_, err = os.Stat(c.PubKey)
	if err != nil {
		return fmt.Errorf("unable to stat public_key '%s' : %v", c.PubKey, err)
	}

	_, err = os.Stat(c.PrivKey)
	if err != nil {
		return fmt.Errorf("unable to stat private_key '%s' : %v", c.PrivKey, err)
	}

	return nil
}
