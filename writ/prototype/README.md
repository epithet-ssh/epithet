# Retired Writ parser spike

This Rust prototype preserves the earlier language design and is not the
current Writ implementation. Its name-based `id:` selector and shorthand
attribute names are obsolete.

Current policies use SCIM field names for scalar selectors and singular
`group:` for membership: `userName:`, `id:`, `group:`,
`userType:`, `department:`, and `organization:`. The current `id:` means
an immutable inventory resource ID; use `userName:` for mutable names.

See [the current specification](../SPEC.md) and the Go implementation in
`../../pkg/writ`. The current scenario corpus is
`../../pkg/writ/testdata/scenarios.writ`.
