.PHONY: build clean init plan apply destroy ca-lambda policy-lambda setup-ca-key

# Build both Lambda functions
build: ca-lambda policy-lambda

# Build CA Lambda function (uses main epithet binary)
ca-lambda:
	@echo "Building CA Lambda function..."
	@mkdir -p bin
	cd ../../ && GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o examples/aws-lambda/bin/bootstrap ./cmd/epithet
	cd bin && zip -q bootstrap-ca.zip bootstrap && rm bootstrap

# Build Policy Lambda function (Go)
policy-lambda:
	@echo "Building Policy Lambda function (Go)..."
	@mkdir -p bin
	cd policy-go && GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o ../bin/bootstrap .
	cd bin && zip -q bootstrap-policy.zip bootstrap && rm bootstrap

# Clean build artifacts
clean:
	rm -rf bin/

# Initialize OpenTofu
init:
	tofu init

# Plan infrastructure changes
plan: build
	tofu plan

# Apply infrastructure changes
apply: build
	tofu apply

# Destroy infrastructure
destroy:
	tofu destroy

# Generate CA key and upload to Secrets Manager
setup-ca-key:
	@echo "Generating CA key..."
	@./scripts/generate-ca-key.sh
