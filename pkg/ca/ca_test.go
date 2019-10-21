package ca_test

import (
	"testing"
	"time"

	"github.com/brianm/epithet/pkg/ca"
	"github.com/brianm/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
)

func TestCA_Sign(t *testing.T) {
	require := require.New(t)

	c, err := ca.New(caPubKey, caPrivKey)
	require.NoError(err)

	cert, err := c.SignPublicKey(sshcert.RawPublicKey(userPubKey), &ca.CertParams{
		Identity:   "brianm",
		Expiration: time.Second * 10000,
		Names:      []string{"root", "deployer"},
	})
	require.NoError(err)

	crt, err := sshcert.Parse(cert)
	require.NoError(err)

	require.Equal("brianm", crt.KeyId)
	require.Equal([]string{"root", "deployer"}, crt.ValidPrincipals)
}

const userPubKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75S brianmn@scuffin`

const caPubKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNH7zWoDN/0GHOqMq8E4l0xehxI4bqcqp4FmjMoGp1gb1VYl+G/KWoRufzamCvVvX37oGfTlIi/0wW/mCFPtVv9Dg6nWGVRz6rECv4hjF4TcxgXIXbVLw70Lwy0FNhc9bX13D+4Z8UkaP94c0s79nbtfW7w82jvnCXwWYh9odr+PX9tSZOCJvWgoGd0/pMbyLp/7EapGByu+fxqx4Xyb89RVtCpBBZrZ7xOqPV5wD5BjHfrCREqcdeV8jzzQkxDUclPjbFga4WWUMEFz3lr8b14yPl0m5ANCRFz2RX7jp8xKiL8gz7V0K37ZX5vHaGgaDHgQbmRvq7BkaGWRYELyzJ user-ca`

const caPrivKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAzR+81qAzf9BhzqjKvBOJdMXocSOG6nKqeBZozKBqdYG9VWJfhvyl
qEbn82pgr1b19+6Bn05SIv9MFv5ghT7Vb/Q4Op1hlUc+qxAr+IYxeE3MYFyF21S8O9C8Mt
BTYXPW19dw/uGfFJGj/eHNLO/Z27X1u8PNo75wl8FmIfaHa/j1/bUmTgib1oKBndP6TG8i
6f+xGqRgcrvn8aseF8m/PUVbQqQQWa2e8Tqj1ecA+QYx36wkRKnHXlfI880JMQ1HJT42xY
GuFllDBBc95a/G9eMj5dJuQDQkRc9kV+46fMSoi/IM+1dCt+2V+bx2hoGgx4EG5kb6uwZG
hlkWBC8syQAAA8DxizNB8YszQQAAAAdzc2gtcnNhAAABAQDNH7zWoDN/0GHOqMq8E4l0xe
hxI4bqcqp4FmjMoGp1gb1VYl+G/KWoRufzamCvVvX37oGfTlIi/0wW/mCFPtVv9Dg6nWGV
Rz6rECv4hjF4TcxgXIXbVLw70Lwy0FNhc9bX13D+4Z8UkaP94c0s79nbtfW7w82jvnCXwW
Yh9odr+PX9tSZOCJvWgoGd0/pMbyLp/7EapGByu+fxqx4Xyb89RVtCpBBZrZ7xOqPV5wD5
BjHfrCREqcdeV8jzzQkxDUclPjbFga4WWUMEFz3lr8b14yPl0m5ANCRFz2RX7jp8xKiL8g
z7V0K37ZX5vHaGgaDHgQbmRvq7BkaGWRYELyzJAAAAAwEAAQAAAQEAx28PJEG4MJIDNnHI
Q1pfb8in+bCIEVSRR5bKKAHj4AHXerfdlxn3WoguJu2LuY68MWWUY7Y7h8leSpDieUqhLG
tvbBXudbxCQwHDLqwSVxyVFC+A+cIGDcYh5OnF199PyKWwODBXgiEkJ8ituv4sfEEK/Zcf
Tg/v2qxvx5+xBRjZOMclfhFvtv+QxsE+yFH9+KZvrtv0GsEHTnCD1FsY1Vh6vZhBBjFNFo
JtKw5KIiXGdmMv9s6cUT4DClG31M2QnvbppQhLrxxdLAGTB0Dr7ldtBZdauhKhPo1TaJMg
3EQZ7IYoyBeCedOagAKb0GW68FW0Tmy73HaRfU8dZgnaDQAAAIAncC8GP72UgX7zxJ19Go
/tpmKyQvtrOjtmZAja0/y+bePYwHllvTfPLEo5NOeiLv8fDTTIPETUMmihywstyU2TPbWq
pgRjXCv36QGYlviKfjja1uIwd9KLJRKavI3kp+0uz6ZJFxrez0i7GCR0Tu2rX+RGrjLj2V
mY+eCroW+y5AAAAIEA5+Hl9hU2Sbx8j6Ohgeyn9eFfVTafRttMg2wMQVNW0MzMj0DibSKT
Fi55TwSANSXMQ/uL3eW6ZcHcxKQCxT2KzTz7QiR3qE2uad9EQx3N6XWKxDoPlDgrlUktcH
nYy4rmJe7HVL7FpBuFUxsfrlgVclrxClA/lZq8mP9CutlZBYcAAACBAOJ1XnwElJpDxwWY
HEM250mpK26m4oxkjBMIx/lLC1DST+vMU2k/N801xi6Rb1MravliiuK0jHZlJO4DL816GV
lTe2/oE0W4DNt/J1ypylVLVL2E2EKqQqHbYmXQ87EFdp8OanAu6F29pRdKstTbYkGk6lET
lYB3IqmowLJ7ac8vAAAAB3VzZXItY2EBAgM=
-----END OPENSSH PRIVATE KEY-----
`
