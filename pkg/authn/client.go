package authn

import (
	fmt "fmt"

	"google.golang.org/grpc"
)

// NewClient creates a new authenticator client
func NewClient(path string) (AuthenticatorClient, error) {
	conn, err := grpc.Dial(fmt.Sprintf("unix:%s", path), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return NewAuthenticatorClient(conn), nil
}
