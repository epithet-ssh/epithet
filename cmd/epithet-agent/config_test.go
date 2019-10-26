package main_test

import (
	"testing"

	"github.com/naoina/toml"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	"gotest.tools/assert"
)

func Test_ParseToml(t *testing.T) {
	raw := []byte(`
[skife]
ca_url = "https://skife-ca.example.org/"
agent_sock = "~/.epithet/skife.identity.sock" 	# default
authn_sock = "~/.epithet/skife.authn.sock"		# default

[xnio]
ca_url = "https://xnio-ca.example.org/"
`)

	agents := map[string]AgentConfig{}
	err := toml.Unmarshal([]byte(raw), &agents)
	require.NoError(t, err)

	assert.Equal(t, "https://skife-ca.example.org/", agents["skife"].CA)
}

func Test_ParseYaml(t *testing.T) {

	raw := `---
skife:
  ca_url: https://skife-ca.example.org/
  agent_sock: ~/.epithet/skife.identity.sock 	# default
  authn_sock: ~/.epithet/skife.authn.sock		# default

xnio:
  ca_url: https://xnio-ca.example.org/
`
	agents := map[string]AgentConfig{}
	err := yaml.Unmarshal([]byte(raw), &agents)
	require.NoError(t, err)

	assert.Equal(t, "https://skife-ca.example.org/", agents["skife"].CA)
}

type AgentConfig struct {
	CA        string `json:"ca_url" yaml:"ca_url" toml:"ca_url"`
	AgentSock string `json:"agent_sock" yaml:"agent_sock" toml:"agent_sock"`
	AuthnSock string `json:"authn_sock" yaml:"authn_sock" toml:"authn_sock"`
}
