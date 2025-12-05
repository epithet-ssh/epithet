.PHONY: all
all: clean test build		## run tests and build binaries

epithet:
	go build ./cmd/epithet

.PHONY: build
build: epithet

.PHONY: test
test:	## run all tests
	go test ./...

.PHONY: clean
clean:			## clean all local resources
	go clean ./...
	go clean -testcache
	rm -rf epithet
	rm -rf dist

.PHONY: clean-all
clean-all: clean
	go clean -cache
	go clean -modcache

.PHONY: release-dry-run
release-dry-run:	## test release locally without publishing
	goreleaser release --snapshot --clean --skip=publish

.PHONY: snapshot
snapshot:		## build snapshot binaries
	goreleaser build --snapshot --clean

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'


VERSION := 0.1.0
docker: 		## build docker image for epithet-ca
	docker buildx build --push --platform linux/amd64 -t ghcr.io/epithet-ssh/epithet-ca:$(VERSION) .
