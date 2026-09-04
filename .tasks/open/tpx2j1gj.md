---
yatl_version: 1
title: Improve static inventory domain validation errors
id: tpx2j1gj
created: 2026-09-04T21:16:45.158342Z
updated: 2026-09-04T21:16:45.158342Z
author: Brian McCallister
priority: high
tags:
- inventory
- diagnostics
- principal-domains
- migration
---

Make static-inventory validation errors identify the operator-facing object
and explain likely remediation instead of exposing only an internal zero-based
slice index and the lowest-level parser error.

The motivating failure was:

```text
/usr/local/etc/epithet/inventory.yaml: hosts[12] domain: named domain must use lowercase ASCII letters, digits, and internal '.', '_', or '-' characters
```

The actual object was `pancake.home`, whose `domain` still contained a legacy
0.23 `epithet-host-v1-*` host ID. The message made the valid generated-domain
syntax look broken, required manually counting entries, and did not explain
that the old value must be replaced through re-enrollment.

Requirements:

- Include the host `name` or `pattern` in every host-entry validation error
  whenever one is available. Retain file location information; prefer a YAML
  line/column if the decoder can provide it reliably, otherwise show both the
  human-readable object and its index.
- Do not make operators reason about zero-based indexes alone. If an ordinal is
  shown, make its convention obvious or use a one-based entry number.
- Detect the legacy `epithet-host-v1-*` namespace explicitly and report that it
  is a pre-principal-domain host ID which cannot be reused. Tell the operator to
  re-enroll the host and copy the newly generated `epithet-host-id-v1:*` domain;
  do not suggest mechanically changing the prefix.
- Keep malformed generated-domain errors distinct from named-domain syntax
  errors, and include the rejected value safely enough to distinguish typos.
- Preserve strict, fail-closed validation. Suggestions are diagnostic only and
  must never autocorrect, create, or join a domain.
- Apply the same contextual wrapping to duplicate declarations, undeclared
  domain references, principal-mode/domain mismatches, and shared-domain
  authorization-attribute conflicts.

Acceptance:

- A fixture containing `pancake.home` with an `epithet-host-v1-*` domain emits
  an error naming `pancake.home`, identifying the legacy format, and directing
  re-enrollment.
- A misspelled named domain, malformed generated domain, and invalid host entry
  each produce a concise message naming the affected host or pattern.
- Tests assert useful stable facts rather than an entire brittle error string.

---
# Log: 2026-09-04T21:16:45Z Brian McCallister

Created task.
