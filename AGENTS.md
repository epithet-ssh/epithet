# Repository guidelines

## Version control
This repository uses Jujutsu (`jj`), not git. Use commands such as `jj status`, `jj commit`, and `jj new` when manipulating history.

## Build and test
Validate changes with `make build` and `make test`. Use `go test -race ./pkg/broker` for concurrency-sensitive paths.

## Task tracking and commits
Use YATL for deferred work and substantial feature plans. Do not create tasks for individual conversation turns, immediate fixes, or review comments. Update existing tasks when the work belongs to a tracked feature. Do not introduce other TODO systems.

Follow Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`) written in the imperative so tooling like `svu next` can infer versions.
