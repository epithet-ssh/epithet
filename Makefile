DOCKER_TEST_SSHD_VERSION := 4

.PHONY: all
all: test build		## run tests and build binaries

pkg/authn/authn.pb.go:
	mkdir -p pkg/authn/
	protoc -I ./proto authn.proto --go_out=plugins=grpc:pkg/authn

.PHONY:protoc
protoc: pkg/authn/authn.pb.go

epithet-agent: protoc
	go build ./cmd/epithet-agent

epithet-ca: 
	go build ./cmd/epithet-ca

epithet-auth: protoc
	go build ./cmd/epithet-auth

.PHONY: build 
build: epithet-agent epithet-ca epithet-auth protoc

.PHONY: test
test: test-support	## build and run test plumbing
	go test ./...

test/test_sshd/.built_$(DOCKER_TEST_SSHD_VERSION):
	cd test/test_sshd; docker build -t brianm/epithet-test-sshd:$(DOCKER_TEST_SSHD_VERSION) .; touch .built_$(DOCKER_TEST_SSHD_VERSION)

.PHONY: test-support 
test-support: protoc test/test_sshd/.built_$(DOCKER_TEST_SSHD_VERSION)

.PHONY: clean
clean:			## clean all local resources
	go clean ./...
	go clean -testcache	
	rm -f epithet-*
	rm -f pkg/authn/*.pb.go
	
.PHONY: clean-all
clean-all: clean
	rm -f test/test_sshd/.built_*
	go clean -cache
	go clean -modcache
	docker rmi -f brianm/epithet-test-sshd:$(DOCKER_TEST_SSHD_VERSION)

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: sshd
sshd:		## start dev/test sshd server on port 2222
	docker run -p 2222:22 --rm -it brianm/epithet-test-sshd:4 /usr/sbin/sshd -d
