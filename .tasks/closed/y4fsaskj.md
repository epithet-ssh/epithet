---
yatl_version: 1
title: Publish Epithet through a FreeBSD pkg repository
id: y4fsaskj
created: 2026-02-23T04:06:46.519858Z
updated: 2026-09-03T23:34:07.723132Z
author: Brian McCallister
priority: high
tags:
- packaging
- freebsd
- release
---

# Publish Epithet through a FreeBSD pkg repository

## Outcome

FreeBSD hosts can install and upgrade Epithet with the native `pkg` client instead of manually downloading and unpacking each GitHub release.

The first useful package is the host-side installation: it installs the `epithet` binary in the normal FreeBSD prefix and supports `epithet host enroll`. Packaging CA and policy-server services, including any `rc.d` scripts, is separate and must not assume the obsolete combined `epithet server` command.

## Work

1. Choose and document the reproducible package-build path (for example, native `pkg` tooling or poudriere) and the supported FreeBSD ABI and architecture matrix.
2. Build versioned `.pkg` artifacts from tagged Epithet releases.
3. Generate and sign repository metadata, with signing-key custody and rotation documented.
4. Publish each supported ABI repository at a stable HTTPS URL.
5. Provide the client repository configuration needed for `pkg install epithet` and `pkg upgrade epithet`.
6. Integrate publication with the release workflow without allowing a partially published release to replace the current repository metadata.
7. Document package ownership and behavior for Epithet configuration and host state. Installation and upgrade must not overwrite enrolled host state; uninstall behavior must be explicit.

## Acceptance

- A clean supported FreeBSD host can add the repository and run `pkg install epithet`.
- The installed binary reports the tagged release version and can run `epithet host enroll`.
- A host with an existing enrollment can run `pkg upgrade epithet` without changing its host ID, CA public key, or generated SSH configuration unexpectedly.
- Repository signatures are verified by clients.
- Both a fresh installation and an upgrade from the preceding Epithet release are tested on every supported ABI/architecture combination.
- Publishing and recovery procedures are documented, including how to roll back repository metadata after a bad package publication.

---
# Log: 2026-02-23T04:06:46Z Brian McCallister

Created task.

---
# Log: 2026-09-03T21:13:41Z Brian McCallister

Refreshed the existing FreeBSD packaging task after v0.23.0: focus the first package on host installation and upgrades, require signed repository publication, preserve enrolled host state, and remove obsolete combined-server assumptions.

---
# Log: 2026-09-03T21:52:38Z Brian McCallister

Started working.

---
# Log: 2026-09-03T23:34:07Z Brian McCallister

Published the signed FreeBSD:15:amd64 repository at pkg.epithet.dev with Poudriere and a read-only Bastille/Caddy serving jail. Verified v0.23.0 through clean port QA, fresh install, v0.22.0-to-v0.23.0 upgrade, signature checking, host-state preservation, uninstall, atomic promotion, and a separate install over the public HTTPS endpoint.

---
# Log: 2026-09-03T23:34:07Z Brian McCallister

Closed.
