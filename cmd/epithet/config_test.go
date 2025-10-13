package main

import (
	"testing"

	"github.com/lithammer/dedent"
	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/require"
)

func Test_ReadConfig(t *testing.T) {
	config_data := dedent.Dedent(`
		[home]
		match = ["m0001", "m0002", "m0003", "m0004"]
		ca_url = "https://ca.home.skife.org/epithet"

		[skife]
		match = ["**.skife.org"]
		ca_url = "https://ca.skife.org/epithet"
	`)
	var cfg map[string]Config
	err := toml.Unmarshal([]byte(config_data), &cfg)
	require.NoError(t, err)

	one, ok := cfg["skife"]
	require.True(t, ok, "skife config should exist")
	require.Equal(t, 1, len(one.Match))

	require.True(t, one.Match[0].Match("freki.skife.org"))
}
