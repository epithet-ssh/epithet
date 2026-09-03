// Package principal implements Epithet's deterministic SSH certificate
// principal schemes. Issuers and target-host authorization helpers share this
// package so the byte-level protocol has one public implementation.
package principal

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math"

	"golang.org/x/crypto/ssh"
)

// SchemeV1 is both the visible prefix of a v1 principal and the domain
// separator framed into its digest input.
const SchemeV1 = "epithet-principal-v1"

// DeriveV1 derives the destination-bound certificate principal for account on
// the host identified by hostKey. The public key is hashed in its canonical
// SSH wire encoding; account is used byte-for-byte.
func DeriveV1(hostKey ssh.PublicKey, account string) (string, error) {
	if hostKey == nil {
		return "", fmt.Errorf("host public key is required")
	}

	h := sha256.New()
	for _, field := range [][]byte{
		[]byte(SchemeV1),
		hostKey.Marshal(),
		[]byte(account),
	} {
		if err := writeSSHString(h, field); err != nil {
			return "", err
		}
	}

	return SchemeV1 + "-" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// writeSSHString writes RFC 4251 string framing: a four-octet unsigned
// big-endian length followed by that many payload octets.
func writeSSHString(dst hash.Hash, value []byte) error {
	if uint64(len(value)) > math.MaxUint32 {
		return fmt.Errorf("SSH string is too large: %d bytes", len(value))
	}

	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	if err := writeAll(dst, size[:]); err != nil {
		return fmt.Errorf("writing SSH string length: %w", err)
	}
	if err := writeAll(dst, value); err != nil {
		return fmt.Errorf("writing SSH string value: %w", err)
	}
	return nil
}

func writeAll(dst io.Writer, value []byte) error {
	n, err := dst.Write(value)
	if err != nil {
		return err
	}
	if n != len(value) {
		return io.ErrShortWrite
	}
	return nil
}
