# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

For architecture details, see [docs/architecture.md](docs/architecture.md).

## Project overview

Epithet is an SSH certificate authority system that makes SSH certificates easy to use. It replaces traditional SSH key-based authentication with certificate-based authentication using per-connection agents.

**v2 is complete and production-ready.** All components are fully implemented: broker with auth command protocol, match command, CA/policy servers, OIDC authentication, per-connection agents, and end-to-end integration tests.

Design notes, future ideas, and exploratory documents are kept in the `ideas/` directory for future reference.

## Correctness over convenience

* Model the full error space—no shortcuts or simplified error handling.
* Handle all edge cases, including race conditions, signal timing, and platform differences.
* Use the type system to encode correctness constraints.
* Prefer compile-time guarantees over runtime checks where possible.

## User experience as a primary driver

* Provide structured, helpful error messages for diagnostics.
* Make progress reporting responsive and informative.
* Maintain consistency across platforms even when underlying OS capabilities differ. Use OS-native logic rather than trying to emulate Unix on Windows (or vice versa).
* Write user-facing messages in clear, present tense: "Epithet now supports..." not "Epithet now supported..."

## Pragmatic incrementalism

* "Not overly generic"—prefer specific, composable logic over abstract frameworks.
* Evolve the design incrementally rather than attempting perfect upfront architecture.
* Document design decisions and trade-offs in design docs.
* When uncertain, explore and iterate.

## Production-grade engineering

* Test comprehensively, including edge cases, race conditions, and stress tests.
* Pay attention to what facilities already exist, and aim to reuse them.
* Getting the details right is really important!

## Documentation

* Use inline comments to explain "why," not just "what".
* Module-level documentation should explain purpose and responsibilities.
* Always use periods at the end of code comments.
* Never use title case in headings and titles. Always use sentence case.

## Commit message conventions

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.
This enables automatic version bumping via `svu next`.

**Format:** `<type>[optional scope]: <description>`

**Types and their version impact:**
- `fix:` → patch bump (0.6.0 → 0.6.1)
- `feat:` → minor bump (0.6.0 → 0.7.0)
- `feat!:` or `BREAKING CHANGE:` → major bump (0.6.0 → 1.0.0)
- `docs:`, `chore:`, `test:`, `refactor:` → no version bump

**Examples:**
- `fix: handle nil pointer in broker auth`
- `feat: add OIDC token refresh support`
- `feat!: change auth command protocol to use fd3`
- `docs: update README with new config format`
- `chore: update dependencies`

## Version control policy

**CRITICAL**: Do NOT create commits or interact with git to make new commits. The user will handle all commit creation.

You are welcome to:
- View commit history (`git log`, `git show`)
- Check git status (`git status`, `git diff`)
- View old commits and changes
- Stage files for review (`git add` to help user see what will be committed)

You must NOT:
- Create commits (`git commit`)
- Push changes (`git push`)
- Create branches (`git checkout -b`)
- Merge or rebase (`git merge`, `git rebase`)

The user prefers to review all changes and craft commit messages themselves.

## Task management with yatl

**CRITICAL**: This project uses yatl (Yet Another Task List) for ALL task tracking. Do NOT use TodoWrite under any circumstances.

When working on tasks:
1. **Always use yatl** - Create tasks with `yatl new`, start with `yatl start`, close with `yatl close`
2. **Use yatl proactively** - For any non-trivial work (multiple steps, complex tasks), create yatl tasks immediately
3. **Track progress** - Use `yatl list` to show current work, `yatl ready` to find unblocked tasks, `yatl next` for suggested task
4. **Log progress** - Use `yatl log <id> "message"` to record progress throughout work
5. **Dependencies matter** - Use `yatl block` to track task dependencies when needed
6. **Never use TodoWrite** - The TodoWrite tool is disabled for this project
7. **ALWAYS close tasks when done** - When you finish implementing a task, immediately run `yatl close <id> --reason "..."`. Check git commits if unsure whether a task was already completed.

Example workflow:
```bash
# Start work on a feature
yatl new "Implement auth command protocol" --priority high --tags feature

# Track subtasks
yatl new "Parse netstring input from stdin" --tags task
yatl new "Invoke auth command and capture output" --tags task
yatl block <task-2-id> <task-1-id>  # task-2 is blocked by task-1

# Start working
yatl start <task-1-id>

# Log progress as you work
yatl log <task-1-id> "Found root cause, implementing fix"

# Close completed work
yatl close <task-1-id> --reason "Completed netstring parser"
```

## Development commands

### Building
```bash
make build          # Build all binaries (epithet, epithet-ca)
make epithet-ca     # Build only the CA server
go build ./cmd/epithet  # Build the epithet CLI
```

### Testing
```bash
make test           # Run all tests
go test ./...       # Alternative: run all tests directly

# Run specific package tests
go test ./pkg/agent
go test ./pkg/ca
go test ./pkg/caserver
go test ./pkg/caclient
go test ./pkg/sshcert

# Run specific test
go test -v ./pkg/agent -run TestBasics
go test -v ./pkg/ca -run TestCA_Sign
```

### Code generation
```bash
make generate       # Generate protobuf code (internal/agent/agent.pb.go)
go generate ./...   # Alternative: run go generate
```

The project uses protobuf for agent communication. Generated files are in `internal/agent/agent.pb.go` and must be regenerated after proto changes.

### Cleanup
```bash
make clean          # Clean build artifacts and test cache
make clean-all      # Clean everything including generated code and module cache
```

## Important constants and limits

- `caserver.RequestBodySizeLimit = 8192`: Maximum HTTP request body size for CA requests
- `pkg/broker/auth.go:maxStateSizeBytes = 10 MiB`: Maximum auth state size
- `pkg/broker/broker.go:maxRetries = 3`: Maximum retry attempts for CA 401 and auth failures
- `pkg/broker/broker.go:expiryBuffer = 5 seconds`: Safety margin for certificate expiry checks
- `pkg/broker/broker.go:cleanupInterval = 30 seconds`: Frequency of expired agent cleanup

## Minor remaining task

Auth command mustache templates don't yet receive connection details (%h, %p, %r, %C).
