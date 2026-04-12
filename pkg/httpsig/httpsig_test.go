package httpsig_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/httpsig"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSignAndVerifyGET(t *testing.T) {
	require := require.New(t)

	signer, err := httpsig.NewSigner(testPrivKey)
	require.NoError(err)
	require.NotEmpty(signer.KeyID())

	req, err := http.NewRequest("GET", "http://localhost/", nil)
	require.NoError(err)

	err = signer.SignRequest(req)
	require.NoError(err)

	require.NotEmpty(req.Header.Get("Signature"))
	require.NotEmpty(req.Header.Get("Signature-Input"))

	// Verify
	verifier, err := httpsig.NewVerifier(testPubKey)
	require.NoError(err)

	err = verifier.VerifyRequest(req)
	require.NoError(err)
}

func TestSignAndVerifyPOST(t *testing.T) {
	require := require.New(t)

	signer, err := httpsig.NewSigner(testPrivKey)
	require.NoError(err)

	body := []byte(`{"token":"abc","connection":{}}`)
	req, err := http.NewRequest("POST", "http://localhost/", bytes.NewReader(body))
	require.NoError(err)
	req.Header.Set("Content-Type", "application/json")

	err = signer.SignRequest(req)
	require.NoError(err)

	require.NotEmpty(req.Header.Get("Signature"))
	require.NotEmpty(req.Header.Get("Signature-Input"))
	require.NotEmpty(req.Header.Get("Content-Digest"))

	// Verify
	verifier, err := httpsig.NewVerifier(testPubKey)
	require.NoError(err)

	err = verifier.VerifyRequest(req)
	require.NoError(err)
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	require := require.New(t)

	signer, err := httpsig.NewSigner(testPrivKey)
	require.NoError(err)

	body := []byte(`{"token":"abc"}`)
	req, err := http.NewRequest("POST", "http://localhost/", bytes.NewReader(body))
	require.NoError(err)

	err = signer.SignRequest(req)
	require.NoError(err)

	// Tamper with the body after signing.
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"token":"xyz"}`)))

	verifier, err := httpsig.NewVerifier(testPubKey)
	require.NoError(err)

	err = verifier.VerifyRequest(req)
	require.Error(err)
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	require := require.New(t)

	signer, err := httpsig.NewSigner(testPrivKey)
	require.NoError(err)

	req, err := http.NewRequest("GET", "http://localhost/", nil)
	require.NoError(err)

	err = signer.SignRequest(req)
	require.NoError(err)

	// Verify with a different key should fail.
	verifier, err := httpsig.NewVerifier(otherPubKey)
	require.NoError(err)

	err = verifier.VerifyRequest(req)
	require.Error(err)
}

func TestRSAKeySupport(t *testing.T) {
	require := require.New(t)

	signer, err := httpsig.NewSigner(rsaPrivKey)
	require.NoError(err)

	req, err := http.NewRequest("GET", "http://localhost/", nil)
	require.NoError(err)

	err = signer.SignRequest(req)
	require.NoError(err)

	verifier, err := httpsig.NewVerifier(rsaPubKey)
	require.NoError(err)

	err = verifier.VerifyRequest(req)
	require.NoError(err)
}

func TestECDSAKeySupport(t *testing.T) {
	require := require.New(t)

	signer, err := httpsig.NewSigner(ecdsaPrivKey)
	require.NoError(err)

	req, err := http.NewRequest("GET", "http://localhost/", nil)
	require.NoError(err)

	err = signer.SignRequest(req)
	require.NoError(err)

	verifier, err := httpsig.NewVerifier(ecdsaPubKey)
	require.NoError(err)

	err = verifier.VerifyRequest(req)
	require.NoError(err)
}

// Test keys — ed25519 pair generated for testing.
var testPrivKey = sshcert.RawPrivateKey(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCwGiy42I6vNkuKgH46fQUfuSN9ks/y1wgP0pRarinK+QAAAJBxYVahcWFW
oQAAAAtzc2gtZWQyNTUxOQAAACCwGiy42I6vNkuKgH46fQUfuSN9ks/y1wgP0pRarinK+Q
AAAEAJYUjuRVzhU6uM6NjZog/qbQjvJ5LkNSk4vJRNIqYMU7AaLLjYjq82S4qAfjp9BR+5
I32Sz/LXCA/SlFquKcr5AAAACXRlc3RAa2V5cwECAwQ=
-----END OPENSSH PRIVATE KEY-----
`)

var testPubKey = func() sshcert.RawPublicKey {
	signer, _ := ssh.ParsePrivateKey([]byte(testPrivKey))
	return sshcert.RawPublicKey(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}()

// A second ed25519 key pair for wrong-key tests.
var otherPubKey = func() sshcert.RawPublicKey {
	return sshcert.RawPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75S other@key")
}()

// RSA test key from ca_test.go.
var rsaPrivKey = sshcert.RawPrivateKey(`-----BEGIN OPENSSH PRIVATE KEY-----
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
`)

var rsaPubKey = func() sshcert.RawPublicKey {
	signer, _ := ssh.ParsePrivateKey([]byte(rsaPrivKey))
	return sshcert.RawPublicKey(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}()

// ECDSA P-256 test key.
var ecdsaPrivKey = sshcert.RawPrivateKey(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQR2aqFe+dYCK2RXN/ymY9ANHrmnyr9Q
0cScH/tIZHn8fjI6tI3kA4K1BhllpB546g7YuAPgKsRpN6RNJI33uBQFAAAAqCQDPrAkAz
6wAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHZqoV751gIrZFc3
/KZj0A0euafKv1DRxJwf+0hkefx+Mjq0jeQDgrUGGWWkHnjqDti4A+AqxGk3pE0kjfe4FA
UAAAAgIbhscbjowC3Bn2fBDvGBC51rk3d8dJ+x9FMEKDhBggEAAAAKdGVzdEBlY2RzYQEC
AwQFBg==
-----END OPENSSH PRIVATE KEY-----
`)

var ecdsaPubKey = func() sshcert.RawPublicKey {
	signer, _ := ssh.ParsePrivateKey([]byte(ecdsaPrivKey))
	return sshcert.RawPublicKey(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}()
