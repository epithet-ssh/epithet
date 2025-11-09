package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// Request from CA
type Request struct {
	Token      string            `json:"token"`
	Signature  string            `json:"signature"`
	Connection policy.Connection `json:"connection"`
}

// Response to CA
type Response struct {
	CertParams ca.CertParams `json:"certParams"`
	Policy     policy.Policy `json:"policy"`
}

func handler(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Parse request body
	var req Request
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return errorResponse(400, fmt.Sprintf("Invalid JSON: %v", err)), nil
	}

	// Verify CA signature
	caPubKey := os.Getenv("CA_PUBLIC_KEY")
	if caPubKey != "" {
		if err := ca.Verify(sshcert.RawPublicKey(caPubKey), req.Token, req.Signature); err != nil {
			return errorResponse(401, fmt.Sprintf("Invalid signature: %v", err)), nil
		}
	}

	// Validate shared secret token
	policySecret := os.Getenv("POLICY_SECRET")
	if policySecret == "" {
		return errorResponse(500, "POLICY_SECRET not configured"), nil
	}
	if req.Token != policySecret {
		return errorResponse(401, "Invalid authentication token"), nil
	}

	// Use the remote user as the principal
	remoteUser := req.Connection.RemoteUser
	if remoteUser == "" {
		remoteUser = "root"
	}

	// 5 minute expiration
	expiration := 5 * time.Minute

	resp := Response{
		CertParams: ca.CertParams{
			Identity:   "personal-user",
			Names:      []string{remoteUser},
			Expiration: expiration,
			Extensions: map[string]string{
				"permit-pty":             "",
				"permit-X11-forwarding":  "",
				"permit-port-forwarding": "",
				"permit-user-rc":         "",
			},
		},
		Policy: policy.Policy{
			HostPattern: "*",
		},
	}

	body, err := json.Marshal(resp)
	if err != nil {
		return errorResponse(500, fmt.Sprintf("Failed to marshal response: %v", err)), nil
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(body),
	}, nil
}

func errorResponse(statusCode int, message string) events.APIGatewayV2HTTPResponse {
	body, _ := json.Marshal(map[string]string{"error": message})
	return events.APIGatewayV2HTTPResponse{
		StatusCode: statusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       string(body),
	}
}

func main() {
	lambda.Start(handler)
}
