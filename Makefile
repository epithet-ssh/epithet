DOCKER_TEST_SSHD_VERSION := 5

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

test/test_sshd/.built_$(DOCKER_TEST_SSHD_VERSION):
	cd test/test_sshd; docker build -t brianm/epithet-test-sshd:$(DOCKER_TEST_SSHD_VERSION) .; touch .built_$(DOCKER_TEST_SSHD_VERSION)

.PHONY: test-support 
test-support: internal/agent/agent.pb.go test/test_sshd/.built_$(DOCKER_TEST_SSHD_VERSION)

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
	docker rmi -f brianm/epithet-test-sshd:$(DOCKER_TEST_SSHD_VERSION)

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: sshd
sshd:			## start dev/test sshd server on port 2222
	docker run -p 2222:22 --rm -it brianm/epithet-test-sshd:4 /usr/sbin/sshd -d
