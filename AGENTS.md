# Repository guidelines

## Version control and workflow
This repository uses Jujutsu (`jj`), not git. Use commands such as `jj status`, `jj commit`, and `jj new` when manipulating history.

## Build and test commands
Primary language is Go. Validate changes with `make build` and `make test` (which wrap `go build ./...` and `go test ./...`). Regenerate protobufs via `make generate` (Buf) whenever files in `proto/` change. Use `go test -race ./pkg/broker` for concurrency-sensitive paths.

## Coding standards
Keep module folders aligned with runtime components (`cmd/epithet`, `pkg/broker`, `pkg/policyserver`). Never edit generated files in `pkg/brokerv1`. Before proposing custom code that wraps or extends a library, check the library's README, docs, and ecosystem for existing companion packages that already solve the problem.

## Task tracking and commits
Track work in `yatl`; do not introduce other TODO systems. Follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`) written in the imperative so tooling like `svu next` can infer versions.

## Important constants
- `caserver.RequestBodySizeLimit = 8192`: maximum HTTP request body size for CA requests.
- `pkg/broker/broker.go:maxRetries = 3`: maximum retry attempts for CA 401 errors and auth failures.
- `pkg/broker/certs.go:expiryBuffer = 5 seconds`: safety margin for certificate expiry checks.
- `pkg/broker/broker.go:cleanupInterval = 30 seconds`: frequency of expired agent cleanup.
