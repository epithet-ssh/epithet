package control

import (
	"fmt"
	"math"
	"time"

	"github.com/epithet-ssh/epithet/internal/jwtkey"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const enrollmentAudience = "epithet-enrollment"

// enrollmentAuthority issues reusable provisioning credentials and verifies
// them against control's configured key. These credentials have no authority
// in the request-bound service protocol. Subject revocation belongs to control.
type enrollmentAuthority struct {
	signer jose.Signer
	key    jwtkey.VerificationKey
}

func newEnrollmentAuthority(key sshcert.RawPrivateKey) (*enrollmentAuthority, error) {
	signer, public, err := jwtkey.NewSigner(key)
	if err != nil {
		return nil, err
	}
	return &enrollmentAuthority{signer: signer, key: public}, nil
}

// issue requires an explicit lifetime in whole seconds. The only upper bound
// prevents timestamp overflow or an expiry the JSON response cannot represent;
// there is no enrollment lifetime policy cap.
func (a *enrollmentAuthority) issue(subject string, seconds int64) (string, time.Time, error) {
	now := time.Now().Unix()
	if subject == "" || seconds <= 0 || seconds > math.MaxInt64-now {
		return "", time.Time{}, fmt.Errorf("subject and a positive lifetime in seconds are required")
	}
	expiry := now + seconds
	expiresAt := time.Unix(expiry, 0).UTC()
	if _, err := expiresAt.MarshalJSON(); err != nil {
		return "", time.Time{}, fmt.Errorf("enrollment expiration cannot be represented: %w", err)
	}
	claims := struct {
		Audience string `json:"aud"`
		Expiry   int64  `json:"exp"`
		Subject  string `json:"sub"`
	}{enrollmentAudience, expiry, subject}
	raw, err := jwt.Signed(a.signer).Claims(claims).Serialize()
	return raw, expiresAt, err
}

// verify returns only a verified, nonempty subject. Expiration is mandatory
// and strict: there is no grace period at or after exp.
func (a *enrollmentAuthority) verify(raw string) (string, error) {
	var claims jwt.Claims
	if err := a.key.Verify(raw, &claims); err != nil {
		return "", err
	}
	if !claims.Audience.Contains(enrollmentAudience) || claims.Expiry == nil || int64(*claims.Expiry) <= time.Now().Unix() || claims.Subject == "" {
		return "", fmt.Errorf("invalid enrollment claims")
	}
	return claims.Subject, nil
}
