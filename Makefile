# Version resolution via svu. Set VERSION to next/patch/minor/major or an explicit version.
VERSION ?= next

GITHUB_TOKEN ?= $(shell gh auth token)
export GITHUB_TOKEN
ifeq ($(VERSION),next)
  V := $(shell svu next)
else ifeq ($(VERSION),patch)
  V := $(shell svu next --force-patch-increment)
else ifeq ($(VERSION),minor)
  V := $(shell svu minor)
else ifeq ($(VERSION),major)
  V := $(shell svu major)
else
  V := $(VERSION)
endif

.PHONY: all
all: clean test build		## run tests and build binaries

.PHONY: generate
generate:		## generate protobuf code
	buf generate

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


.PHONY: next-version
next-version:		## show current and next version
	@echo "current: $$(svu current)"
	@echo "next:    $$(svu next)"

.PHONY: release
release: test	## tag and release (VERSION=next|patch|minor|major|x.y.z)
	git tag -a v$(V) -m "v$(V)"
	git push origin v$(V)
	goreleaser release --clean

