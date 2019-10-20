DOCKER_TEST_SSHD_VERSION := 4

.PHONY: all
all: test build		## run tests and build binaries

epithet:
	go build ./cmd/epithet

.PHONY: build 
build: epithet

.PHONY: test
test: test-support	## build and run test plumbing
	go test ./...

test/test_sshd/.built_$(DOCKER_TEST_SSHD_VERSION):
	cd test/test_sshd; docker build -t brianm/epithet-test-sshd:$(DOCKER_TEST_SSHD_VERSION) .; touch .built_$(DOCKER_TEST_SSHD_VERSION)

.PHONY: test-support
test-support: test/test_sshd/.built_$(DOCKER_TEST_SSHD_VERSION)

.PHONY: clean
clean:			## clean all local resources
	go clean ./...
	rm -f epithet
	
.PHONY: clean-all
clean-all: clean
	rm -f test/test_sshd/.built_*
	docker rmi -f brianm/epithet-test-sshd:$(DOCKER_TEST_SSHD_VERSION)

.PHONY: help
help:			## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
