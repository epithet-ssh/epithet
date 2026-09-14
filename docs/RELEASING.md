# Releasing

Stable releases use an annotated `vX.Y.Z` source tag. GitHub Actions produces
optional binary archives. FreeBSD, Arch, and Homebrew packaging are owned by
[`epithet-ssh/epithet-packaging`](https://github.com/epithet-ssh/epithet-packaging)
and can run independently of Actions.

## Quick procedure

```bash
jj st                   # confirm the intended source revision
make next-version       # sanity-check current vs. computed next version
make release            # runs tests, then creates the annotated tag
git push origin vX.Y.Z  # publish the tag to the configured source remote
```

The self-hosted packaging builder can start immediately with
`epithet-release release vX.Y.Z FULL_SOURCE_COMMIT`. Its optional one-minute
source-tag poll provides a fallback. It checks the tag's exact commit, prepares a
vendored source archive, and runs three independent jobs: native FreeBSD builds
and package tests, Arch builds and package tests on a Linux VM, and macOS
cross-compilation followed by a Homebrew tap update. macOS packaging tests are
not run in v1. One failed target does not block the others.

Check the packaging builder's status and per-target logs to confirm publication.
A green GitHub release workflow only confirms its optional download artifacts.
The packaging repository contains setup, signing, VM, serving, and rollout
instructions. This machinery must be deployed before its automatic packaging
flow is active. Coordinate removing the old GoReleaser Homebrew writer with that
cutover; this source change transfers tap ownership to the packaging builder.

## How the version is chosen

`make release` uses [`svu`](https://github.com/caarlos0/svu), which reads
Conventional Commits since the last tag to compute the next version:

- `fix:` → patch (`0.17.1` → `0.17.2`)
- `feat:` → minor (`0.17.1` → `0.18.0`)
- `feat!:` or a `BREAKING CHANGE:` footer → major (`0.17.1` → `1.0.0`)

This is why commits must follow Conventional Commits — the version number is
derived from them, not chosen by hand.

Override the bump when needed via `VERSION`:

```bash
make release VERSION=patch    # force a patch bump
make release VERSION=minor    # force a minor bump
make release VERSION=major    # force a major bump
make release VERSION=0.17.5   # pin an explicit version
```

`make release VERSION=next` (the default) is the `svu`-computed value.

## The trigger model

Two workflows split CI from releasing on the tag:

- `.github/workflows/build.yml` runs on every branch and pull request but
  **ignores `v*` tags** (`tags-ignore`). Pushing code never releases.
- `.github/workflows/release.yml` runs **only on `v*` tags**. Pushing the tag
  is the release trigger.

These triggers describe GitHub archives. The packaging builder reads stable
source tags directly and does not wait for the GitHub workflow.

## What CI produces

`release.yml` runs one job:

1. **release** — checks out full history, runs `make test`, then goreleaser
   (`release --clean`, config in `.goreleaser.yaml`). goreleaser builds six
   binaries (linux, darwin, freebsd × amd64, arm64), publishes a GitHub Release
   with a filtered changelog and `checksums.txt`. It does not update Homebrew;
   that tap has a single writer in the packaging builder.

## Required secrets

Only the Actions-provided `GITHUB_TOKEN` is needed for GitHub archive releases.
The packaging builder manages its own signing keys and Git tap credentials;
those do not belong in source CI.

## Dry run before cutting a tag

Test the goreleaser build locally without publishing anything:

```bash
make release-dry-run   # goreleaser release --snapshot --clean --skip=publish
```

Artifacts land in `dist/`. Use this to catch build or config problems before
creating a real tag.

## Note on jj

This repository uses `jj`, but `make release` calls `git tag -a` (jj and git
share the same colocated repo). Make sure the working copy is committed
(`jj st` clean) before running `make release` so the tag lands on the intended
commit.
