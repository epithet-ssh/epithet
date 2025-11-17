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
	"github.com/epithet-ssh/epithet/pkg/policyserver"
)

// lambdaPolicyEvaluator implements policyserver.PolicyEvaluator for AWS Lambda
type lambdaPolicyEvaluator struct {
	policySecret string
}

func (e *lambdaPolicyEvaluator) Evaluate(token string, conn policy.Connection) (*policyserver.Response, error) {
	// Validate shared secret token
	if e.policySecret == "" {
		return nil, policyserver.InternalError("POLICY_SECRET not configured")
	}
	if token != e.policySecret {
		return nil, policyserver.Unauthorized("Invalid authentication token")
	}

	// Use the remote user as the principal
	remoteUser := conn.RemoteUser
	if remoteUser == "" {
		remoteUser = "root"
	}

	// 5 minute expiration
	expiration := 5 * time.Minute

	return &policyserver.Response{
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
	}, nil
}

func handler(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Create evaluator with environment config
	evaluator := &lambdaPolicyEvaluator{
		policySecret: os.Getenv("POLICY_SECRET"),
	}

	// Parse request body
	var req policyserver.Request
	if err := json.Unmarshal([]byte(request.Body), &req); err != nil {
		return errorResponse(400, fmt.Sprintf("Invalid JSON: %v", err)), nil
	}

	// Verify CA signature if configured
	caPubKey := os.Getenv("CA_PUBLIC_KEY")
	if caPubKey != "" {
		if err := ca.Verify([]byte(caPubKey), req.Token, req.Signature); err != nil {
			return errorResponse(401, fmt.Sprintf("Invalid signature: %v", err)), nil
		}
	}

	// Evaluate policy
	resp, err := evaluator.Evaluate(req.Token, req.Connection)
	if err != nil {
		// Check if it's a PolicyError with specific status code
		if policyErr, ok := err.(*policyserver.PolicyError); ok {
			return errorResponse(policyErr.StatusCode, policyErr.Message), nil
		}
		// Default to 500 for unknown errors
		return errorResponse(500, err.Error()), nil
	}

	// Success: return policy response
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
