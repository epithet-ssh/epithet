package sshd_test

import (
	"fmt"
	"testing"

	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
)

func Test_Basics(t *testing.T) {
	sshd, err := sshd.StartSSHD(_caPubKey)
	require.NoError(t, err)

	port := sshd.Port()
	require.Greater(t, port, 1023)

	require.FileExists(t, fmt.Sprintf("%s/ssh_host_rsa_key", sshd.Dir))
	require.FileExists(t, fmt.Sprintf("%s/ca.pub", sshd.Dir))
	require.FileExists(t, fmt.Sprintf("%s/sshd_config", sshd.Dir))

	err = sshd.Close()
	require.NoError(t, err)
}

const _caPubKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNH7zWoDN/0GHOqMq8E4l0xehxI4bqcqp4FmjMoGp1gb1VYl+G/KWoRufzamCvVvX37oGfTlIi/0wW/mCFPtVv9Dg6nWGVRz6rECv4hjF4TcxgXIXbVLw70Lwy0FNhc9bX13D+4Z8UkaP94c0s79nbtfW7w82jvnCXwWYh9odr+PX9tSZOCJvWgoGd0/pMbyLp/7EapGByu+fxqx4Xyb89RVtCpBBZrZ7xOqPV5wD5BjHfrCREqcdeV8jzzQkxDUclPjbFga4WWUMEFz3lr8b14yPl0m5ANCRFz2RX7jp8xKiL8gz7V0K37ZX5vHaGgaDHgQbmRvq7BkaGWRYELyzJ user-ca`
