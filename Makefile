.PHONY: all
all: test build		## run tests and build binaries

epithet-agent: internal/agent/agent.pb.go
	go build ./cmd/epithet-agent

epithet-ca: 
	go build ./cmd/epithet-ca

epithet-auth: internal/agent/agent.pb.go
	go build ./cmd/epithet-auth

.PHONY: generate
generate: internal/agent/agent.pb.go

internal/agent/agent.pb.go:
	go generate ./...

.PHONY: build 
build: internal/agent/agent.pb.go epithet-agent epithet-ca epithet-auth

.PHONY: test
test: test-support	## build and run test plumbing
	go test ./...

.PHONY: test-support 
test-support: internal/agent/agent.pb.go 

.PHONY: clean
clean:			## clean all local resources
	go clean ./...
	go clean -testcache	
	rm -f epithet-*
	rm -rf dist

.PHONY: clean-all
clean-all: clean
	rm -f test/test_sshd/.built_*
	go clean -cache
	go clean -modcache
	rm -rf internal/agent/agent.pb.go

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'


VERSION := 0.1.0
docker: 		## build docker image for epithet-ca
	docker buildx build --push --platform linux/amd64 -t ghcr.io/epithet-ssh/epithet-ca:$(VERSION) .
