# Repository Guidelines

## communication style
Answer every direct question first, then describe next steps or alternatives. Stay focused on the user’s immediate request; do not propose architecture shifts unless asked. Ask for clarification only when essential, and prefer execution or code reading over speculation.

## version control and workflow
This repository uses Jujutsu (`jj`), not git. Use commands such as `jj status`, `jj commit`, and `jj new` when manipulating history. Keep work in logical, reviewable stacks and avoid rewriting commits that belong to others without coordination.

## build and test commands
Primary language is Go. Always validate changes with `make build` and `make test` (which wrap `go build ./...` and `go test ./...`). Regenerate protobufs via `make generate` (Buf) whenever files in `proto/` change. Clean build artifacts using `make clean` or `make clean-all` before release builds to ensure reproducibility.

## coding and engineering standards
Prefer straightforward, composable Go code. Encode invariants in types whenever possible and treat error handling comprehensively—model every failure mode and provide actionable error messages. Default to camelCase identifiers, keep module folders aligned with runtime components (`cmd/epithet`, `pkg/broker`, `pkg/policyserver`), and never edit generated files in `pkg/brokerv1`. Before proposing custom code that wraps or extends a library, check the library's README, docs, and ecosystem for existing companion packages that already solve the problem.

## debugging and validation
Investigate the exact symptom described; confirm behavior by reading source or running the code rather than relying on conventions. Add regression tests when fixing bugs and include stress or race tests for concurrency-sensitive paths (`go test -race ./pkg/broker`). When in doubt, reproduce issues with minimal commands instead of wide-ranging exploration.

## documentation and comments
All headings and titles must use sentence case. Comments should explain “why” rather than “what,” end with periods, and accompany exported APIs. Architecture, authentication, and policy docs live under `docs/`; keep them synchronized with code-level changes.

## task tracking and commits
Track work in `yatl`; do not introduce other TODO systems. Follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`) written in the imperative so tooling like `svu next` can infer versions. Pull requests must summarize intent, include validation steps (`make test`, specific `go test` packages), and attach relevant screenshots or logs.

## important constants
Key limits include `caserver.RequestBodySizeLimit = 8192`, `pkg/broker/auth.go:maxStateSizeBytes = 10 MiB`, `pkg/broker/broker.go:maxRetries = 3`, `pkg/broker/broker.go:expiryBuffer = 5 seconds`, and `pkg/broker/broker.go:cleanupInterval = 30 seconds`. Keep these constraints in mind when modifying request handling, state storage, or cleanup loops.
