package sshd_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
)

func Test_Basics(t *testing.T) {
	pubkey, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	s, err := sshd.Start(pubkey)
	require.NoError(t, err)
	defer s.Close()

	t.Log(s.Output.String())

	require.Contains(t, s.Output.String(), "Server listening on")

}
