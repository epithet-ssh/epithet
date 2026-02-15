# CLAUDE.md

## Communication style

When I ask a question, answer it directly before proposing solutions. Do not jump ahead multiple steps or suggest architectural changes unless asked. Stay focused on my immediate question.

## Version control

This project uses `jj` (Jujutsu) for version control, not git. Use jj commands (jj commit, jj bookmark, jj new, etc.) unless explicitly told otherwise.

## Working principles

Always verify assumptions against actual code before confirming behavior. Do not confirm how config/code works based on convention or naming alone — read the source.

## Language and build

Primary language: Go. Run `go build ./...` and `go test ./...` after changes.

## Debugging

When debugging, focus on the specific symptom described. Do not go on extended autonomous exploration or ask multiple clarifying questions in sequence — investigate the direct cause first, then broaden if needed.

For architecture details, see [docs/architecture.md](docs/architecture.md).

## Engineering principles

* Model the full error space — no shortcuts or simplified error handling.
* Handle all edge cases, including race conditions, signal timing, and platform differences.
* Use the type system to encode correctness constraints; prefer compile-time guarantees over runtime checks.
* Provide structured, helpful error messages. Write user-facing messages in clear, present tense.
* Prefer specific, composable logic over abstract frameworks. Evolve design incrementally.
* Test comprehensively, including edge cases, race conditions, and stress tests.
* Reuse existing facilities. Getting the details right is really important.

## Documentation

* Use inline comments to explain "why," not just "what".
* Module-level documentation should explain purpose and responsibilities.
* Always use periods at the end of code comments.
* Never use title case in headings and titles. Always use sentence case.

## Commit messages

Use conventional commits (see commit-conventions skill). This enables version bumping via `svu next`.

## Task management

Use `yatl` for all task tracking (see yatl skill). Never use TodoWrite.

## Development commands

```bash
make build          # Build all binaries
make test           # Run all tests
make generate       # Generate protobuf code (regenerate after proto changes)
make clean          # Clean build artifacts and test cache
```

Specific tests: `go test -v ./pkg/agent -run TestBasics`

## Important constants and limits

- `caserver.RequestBodySizeLimit = 8192`: maximum HTTP request body size for CA requests.
- `pkg/broker/auth.go:maxStateSizeBytes = 10 MiB`: maximum auth state size.
- `pkg/broker/broker.go:maxRetries = 3`: maximum retry attempts for CA 401 and auth failures.
- `pkg/broker/broker.go:expiryBuffer = 5 seconds`: safety margin for certificate expiry checks.
- `pkg/broker/broker.go:cleanupInterval = 30 seconds`: frequency of expired agent cleanup.
