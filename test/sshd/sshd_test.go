package sshd_test

import (
	"context"
	"testing"

	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/stretchr/testify/require"
)

func Test_Basics(t *testing.T) {
	ctx := context.Background()
	sshd, err := sshd.StartSSHD(ctx)
	require.NoError(t, err)

	err = sshd.Close(ctx)
	require.NoError(t, err)
}
