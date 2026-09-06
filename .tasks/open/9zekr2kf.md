---
yatl_version: 1
title: Keep enrolled sshd trust paths root-controlled after symlink resolution
id: 9zekr2kf
created: 2026-09-06T03:17:30.366453Z
updated: 2026-09-06T03:18:13.874473Z
author: Brian McCallister
priority: medium
tags:
- security
- host
- release
---

Security review SR-03 (medium, local attacker and nondefault enrollment path prerequisite), reviewed revision 9e53288f. cmd/epithet/host_sshd_access_unix.go validates ownership only after EvalSymlinks, while configureSSHD/renderSSHDFragment emit the original paths. A symlink under an unprivileged user's directory can initially point to a root-controlled target, pass the gate, then be replaced by that user after configuration. TrustedUserCAKeys may subsequently resolve to an attacker CA. The domain and helper paths need the same audit.

The local probe confirms the ownership gate, emitted path, and unprivileged replacement. It deliberately uses a root-owned system file as an ownership fixture, does not validate enrollment contents, and does not claim a reproduced privileged SSH login. Default root-controlled directories are not shown vulnerable.

Ensure paths persisted into sshd configuration are the same root-controlled paths actually validated, and ensure every path component/symlink used to reach them cannot be replaced by an unprivileged user. Preserve macOS system symlinks safely. Audit custom main/fragment paths too.

Reproduce as an unprivileged user: GOCACHE=/tmp/epithet-go-build-cache go test -tags securityreview -run TestReviewEnrollment -v ./cmd/epithet. Convert probe to a normal rejection or safe-canonical-path regression. Review report: docs/security-review-2026-09-05.md.

---
# Log: 2026-09-06T03:17:30Z Brian McCallister

Created task.
