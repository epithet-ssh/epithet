package sshd_test

import (
	"testing"

	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
)

func Test_Basics(t *testing.T) {
	s, err := sshd.Start()
	require.NoError(t, err)

	defer s.Close()
}
