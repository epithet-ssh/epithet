package writpolicy

import (
	"net/http"

	"github.com/epithet-ssh/epithet/pkg/wire"
)

// forbidden returns an explicit policy denial.
func forbidden(message string) error {
	return &wire.PolicyError{StatusCode: http.StatusForbidden, Message: message}
}
