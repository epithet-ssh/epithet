package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

type AWSCLI struct {
	CA AwsCALambdaCLI `cmd:"ca" help:"Run CA server as AWS Lambda function"`
}

type AwsCALambdaCLI struct {
	SecretArn string `help:"ARN of Secrets Manager secret containing CA private key" env:"CA_SECRET_ARN" required:"true"`
	PolicyURL string `help:"URL of policy validation service" env:"POLICY_URL" required:"true"`
}

type caSecretValue struct {
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	CreatedAt  string `json:"created_at"`
}

func (a *AwsCALambdaCLI) Run(logger *slog.Logger) error {
	logger.Info("starting CA Lambda handler", "policy_url", a.PolicyURL)

	// Load AWS SDK config
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Get CA private key from Secrets Manager
	smClient := secretsmanager.NewFromConfig(cfg)
	result, err := smClient.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: &a.SecretArn,
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve secret: %w", err)
	}

	// Parse secret value
	var secret caSecretValue
	if err := json.Unmarshal([]byte(*result.SecretString), &secret); err != nil {
		return fmt.Errorf("failed to parse secret: %w", err)
	}

	if secret.PrivateKey == "" {
		return fmt.Errorf("CA private key not set in secret - generate one with the setup script")
	}

	// Create CA instance
	caInstance, err := ca.New(sshcert.RawPrivateKey(secret.PrivateKey), a.PolicyURL)
	if err != nil {
		return fmt.Errorf("failed to create CA: %w", err)
	}

	// Create HTTP handler
	handler := caserver.New(caInstance, logger, &http.Client{})

	logger.Info("CA Lambda initialized successfully")

	// Start Lambda handler
	lambda.Start(func(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
		return handleLambdaRequest(ctx, request, handler, logger)
	})

	return nil
}

func handleLambdaRequest(ctx context.Context, request events.APIGatewayV2HTTPRequest, handler http.Handler, logger *slog.Logger) (events.APIGatewayV2HTTPResponse, error) {
	// Create http.Request from API Gateway event
	req, err := http.NewRequestWithContext(ctx, request.RequestContext.HTTP.Method, request.RawPath, nil)
	if err != nil {
		logger.Error("failed to create request", "error", err)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 500,
			Body:       "Internal server error",
		}, nil
	}

	// Add headers
	for k, v := range request.Headers {
		req.Header.Set(k, v)
	}

	// Add body if present
	if request.Body != "" {
		req.Body = io.NopCloser(strings.NewReader(request.Body))
		req.ContentLength = int64(len(request.Body))
	}

	// Create custom response writer
	rw := &lambdaResponseWriter{
		headers: make(http.Header),
		body:    make([]byte, 0),
	}

	// Handle the request
	handler.ServeHTTP(rw, req)

	// Convert headers to map[string]string for API Gateway
	headers := make(map[string]string)
	for k, v := range rw.headers {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: rw.statusCode,
		Headers:    headers,
		Body:       string(rw.body),
	}, nil
}

// lambdaResponseWriter implements http.ResponseWriter for Lambda
type lambdaResponseWriter struct {
	headers    http.Header
	body       []byte
	statusCode int
}

func (w *lambdaResponseWriter) Header() http.Header {
	return w.headers
}

func (w *lambdaResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	if w.statusCode == 0 {
		w.statusCode = 200
	}
	return len(b), nil
}

func (w *lambdaResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}
