.PHONY: all
all: test build		## run tests and build binaries

epithet-agent: 
	go build ./cmd/epithet-agent

epithet-ca: 
	go build ./cmd/epithet-ca

.PHONY: build 
build: test epithet-agent epithet-ca  

.PHONY: test
test:	## build and run test plumbing
	go test ./...

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

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

VERSION := 0.2.0
docker: 		## build docker image for epithet-ca
	docker buildx build --push --platform linux/amd64 -t ghcr.io/epithet-ssh/epithet-ca:$(VERSION) .
