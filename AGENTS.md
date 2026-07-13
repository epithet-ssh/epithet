# Repository guidelines

## Version control
This repository uses Jujutsu (`jj`), not git. Use commands such as `jj status`, `jj commit`, and `jj new` when manipulating history.

## Build and test
Validate changes with `make build` and `make test`. Regenerate protobufs via `make generate` (Buf) whenever files in `proto/` change. Use `go test -race ./pkg/broker` for concurrency-sensitive paths. Never edit generated files in `pkg/brokerv1`.

## Task tracking and commits
Track work in `yatl`; do not introduce other TODO systems. Follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`) written in the imperative so tooling like `svu next` can infer versions.
