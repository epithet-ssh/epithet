package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	policyconfig "github.com/epithet-ssh/epithet/pkg/policyserver/config"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
)

type AWSCLI struct {
	CA     AwsCALambdaCLI     `cmd:"ca" help:"Run CA server as AWS Lambda function"`
	Policy AwsPolicyLambdaCLI `cmd:"policy" help:"Run policy server as AWS Lambda function"`
}

type AwsCALambdaCLI struct {
	SecretArn         string `help:"ARN of Secrets Manager secret containing CA private key" env:"CA_SECRET_ARN" required:"true"`
	PolicyURL         string `help:"URL of policy validation service" env:"POLICY_URL" required:"true"`
	CertArchiveBucket string `help:"S3 bucket for certificate archival (optional)" env:"CERT_ARCHIVE_BUCKET"`
	CertArchivePrefix string `help:"S3 key prefix for certificate archival (optional)" env:"CERT_ARCHIVE_PREFIX" default:"certs"`
}

type caSecretValue struct {
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	CreatedAt  string `json:"created_at"`
}

func (a *AwsCALambdaCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	logger.Info("starting CA Lambda handler", "policy_url", a.PolicyURL)

	// Validate policy URL requires TLS (unless --insecure)
	if err := tlsCfg.ValidateURL(a.PolicyURL); err != nil {
		return err
	}

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
	caInstance, err := ca.New(sshcert.RawPrivateKey(secret.PrivateKey), a.PolicyURL, ca.WithTLSConfig(tlsCfg))
	if err != nil {
		return fmt.Errorf("failed to create CA: %w", err)
	}

	// Create certificate loggers
	certLogger := a.createCertLogger(cfg, logger)

	// Create HTTP client with TLS config
	httpClient, err := tlsconfig.NewHTTPClient(tlsCfg)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Create HTTP handler
	handler := caserver.New(caInstance, logger, httpClient, certLogger)

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

// createCertLogger creates a certificate logger based on configuration.
// If S3 bucket is configured, returns MultiCertLogger with slog + S3.
// Otherwise, returns SlogCertLogger only.
func (a *AwsCALambdaCLI) createCertLogger(cfg aws.Config, logger *slog.Logger) caserver.CertLogger {
	slogLogger := caserver.NewSlogCertLogger(logger)

	// If no S3 bucket configured, use slog only
	if a.CertArchiveBucket == "" {
		logger.Info("certificate archival disabled (no S3 bucket configured)")
		return slogLogger
	}

	// Create S3 client and archiver
	s3Client := s3.NewFromConfig(cfg)
	s3Archiver := caserver.NewS3CertArchiver(caserver.S3ArchiverConfig{
		S3Client:   s3Client,
		Bucket:     a.CertArchiveBucket,
		KeyPrefix:  a.CertArchivePrefix,
		Logger:     logger,
		BufferSize: 100,
	})

	logger.Info("certificate archival enabled",
		"bucket", a.CertArchiveBucket,
		"prefix", a.CertArchivePrefix)

	// Return multi-logger combining slog and S3
	return caserver.NewMultiCertLogger(slogLogger, s3Archiver)
}

type AwsPolicyLambdaCLI struct {
	PolicyParameterName string `help:"SSM Parameter Store parameter name containing policy configuration" env:"POLICY_PARAMETER_NAME" required:"true"`
}

func (a *AwsPolicyLambdaCLI) Run(logger *slog.Logger, tlsCfg tlsconfig.Config) error {
	logger.Info("starting policy Lambda handler", "parameter_name", a.PolicyParameterName)

	// Load AWS SDK config
	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Get policy configuration from SSM Parameter Store
	ssmClient := ssm.NewFromConfig(awsCfg)
	paramResult, err := ssmClient.GetParameter(context.Background(), &ssm.GetParameterInput{
		Name:           &a.PolicyParameterName,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve SSM parameter: %w", err)
	}

	// Write parameter value to temp file and load
	tmpFile := "/tmp/policy.yaml"
	if err := os.WriteFile(tmpFile, []byte(*paramResult.Parameter.Value), 0644); err != nil {
		return fmt.Errorf("failed to write policy config: %w", err)
	}

	cfg, err := policyconfig.LoadFromFile(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to load policy config: %w", err)
	}
	logger.Info("loaded policy config from SSM Parameter Store")

	logger.Info("policy configuration loaded",
		"users", len(cfg.Users),
		"hosts", len(cfg.Hosts),
		"oidc_issuer", cfg.OIDC.Issuer,
		"oidc_audience", cfg.OIDC.Audience,
		"ca_public_key_length", len(cfg.CAPublicKey))

	// Create policy evaluator
	ctx := context.Background()
	eval, err := evaluator.New(ctx, cfg, tlsCfg)
	if err != nil {
		return fmt.Errorf("failed to create policy evaluator: %w", err)
	}

	// Create policy server handler
	handler := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: sshcert.RawPublicKey(cfg.CAPublicKey),
		Evaluator:   eval,
	})

	logger.Info("policy Lambda initialized successfully")

	// Start Lambda handler
	lambda.Start(func(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
		return handleLambdaRequest(ctx, request, handler, logger)
	})

	return nil
}
