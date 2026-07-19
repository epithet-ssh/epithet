# Releasing

Releases are triggered by pushing an annotated `vX.Y.Z` git tag. Everything
downstream — building binaries, publishing the GitHub Release, updating the
Homebrew tap, and building the FreeBSD package — is automated in CI. You never
run goreleaser by hand for a real release; you only create and push the tag.

## Quick procedure

```bash
jj st                   # confirm the working copy is clean and committed
make next-version       # sanity-check current vs. computed next version
make release            # runs tests, then creates the vX.Y.Z tag
git push origin vX.Y.Z  # this push is what triggers the release (make release prints it)
```

Then watch the `release` workflow in GitHub Actions and confirm the GitHub
Release, its `checksums.txt`, and the updated formula in the
`epithet-ssh/homebrew-tap` repository.

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

So a release happens exactly when — and only when — a `v*` tag is pushed.

## What CI produces

`release.yml` runs two jobs:

1. **release** — checks out full history, runs `make test`, then goreleaser
   (`release --clean`, config in `.goreleaser.yaml`). goreleaser builds six
   binaries (linux, darwin, freebsd × amd64, arm64), publishes a GitHub Release
   with a filtered changelog and `checksums.txt`, and pushes an updated formula
   to `epithet-ssh/homebrew-tap`.
2. **freebsd-pkg** — after the release job, builds the FreeBSD `.pkg` in a
   FreeBSD VM (`contrib/freebsd`) and uploads it to the same release.

## Required secrets

`release.yml` needs `HOMEBREW_TAP_GITHUB_TOKEN` (a token with write access to
`epithet-ssh/homebrew-tap`) so goreleaser can push the formula update.
`GITHUB_TOKEN` is provided automatically by Actions.

## Dry run before cutting a tag

Test the goreleaser build locally without publishing anything:

```bash
make release-dry-run   # goreleaser release --snapshot --clean --skip=publish
```

Artifacts land in `dist/`. Use this to catch build or config problems before
creating a real tag.

The dry run currently prints a deprecation warning: the `brews:` block in
`.goreleaser.yaml` is deprecated in favor of `homebrew_casks` (see
<https://goreleaser.com/deprecations#brews>). It still works with the pinned
`~> v2` goreleaser, but should be migrated before bumping goreleaser to a
version that removes it.

## Note on jj

This repository uses `jj`, but `make release` calls `git tag -a` (jj and git
share the same colocated repo). Make sure the working copy is committed
(`jj st` clean) before running `make release` so the tag lands on the intended
commit.
