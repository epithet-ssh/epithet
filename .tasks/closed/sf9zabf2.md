---
yatl_version: 1
title: Reject unverified OIDC email identity bindings
id: sf9zabf2
created: 2026-09-06T03:17:30.351149Z
updated: 2026-09-06T03:40:18.232513Z
author: Brian McCallister
priority: high
tags:
- security
- oidc
- release
---

Fix SR-01 by binding static inventory users to a required, unique oidc-subject under the policy server's single configured/verified OIDC issuer. Token validation keeps signature, issuer, audience, and expiry checks and requires a nonempty subject. Email and email_verified never select the authorization identity, and there is no userName/email fallback.

Writ still evaluates the administrator-controlled userName, groups, and attributes. Certificate and audit identity use that userName. An email change leaves the subject binding intact; an intentional inventory rename changes id: rules while preserving group/attribute matching.

The epithet identity --ca-url command authenticates through the existing CA's discovery, verifies the resulting token, and prints only issuer/subject. It needs no certificate or inventory permission and supports obtaining the binding before deploying the new server. Static examples and docs describe the intentionally breaking migration; old user records fail startup until oidc-subject is added.

Validation: make test passed, including real TLS OIDC-to-policy-to-CA regressions against email impersonation (false, missing, and true email verification), userName fallback, missing subjects, and successful bound-subject issuance after email changes or without email. Validator tests cover malformed subjects and wrong issuer with the same signing key/subject; inventory tests cover duplicate/missing/case-sensitive bindings. Rename tests preserve the intended Writ behavior. Broker race tests passed; make build plus explicit go build succeeded; identity --help and example policy --check passed. The securityreview-tag build also passes the subject regression after extracting the old exploit probe into the normal suite.

Security report: docs/security-review-2026-09-05.md. Migration instructions: docs/policy-server.md, Migrating from email lookup. No deployed server or real identity binding was changed. SR-02 and SR-03 remain separate open tasks.

---
# Log: 2026-09-06T03:17:30Z Brian McCallister

Created task.

---
# Log: 2026-09-06T03:30:06Z Brian McCallister

Started working.

---
# Log: 2026-09-06T03:30:06Z Brian McCallister

User approved a deliberate breaking migration to subject binding: one current user, no compatibility fallback needed. Implement required oidc-subject per static user under the single configured/validated OIDC issuer; preserve userName for Writ and audit identity; reject missing and duplicate subjects. Add a verified identity discovery command and migrate the exploit probe into normal rejection tests.

---
# Log: 2026-09-06T03:40:18Z Brian McCallister

Implemented subject-only authentication binding and verified the migration safeguards. All required build/tests, broker race tests, new certificate regression, identity output checks, and example config validation passed. Production deployment remains unchanged.

---
# Log: 2026-09-06T03:40:18Z Brian McCallister

Closed.
