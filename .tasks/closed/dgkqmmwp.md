---
yatl_version: 1
title: Default agent identity to tab-delimited output with optional JSON
id: dgkqmmwp
created: 2026-09-07T16:52:06.761048Z
updated: 2026-09-07T16:53:31.582856Z
author: Brian McCallister
priority: medium
---

Make epithet agent identity print tab-delimited field/value rows by default, retain JSON with --json, and document both formats. Preserve optional claim omission and stderr login progress.

---
# Log: 2026-09-07T16:52:06Z Brian McCallister

Created task.

---
# Log: 2026-09-07T16:52:57Z Brian McCallister

Started working.

---
# Log: 2026-09-07T16:53:31Z Brian McCallister

Implemented tab-delimited field/value output and --json/-j. Updated documentation and exercised CLI flag parsing, both output formats, optional verification omission versus false, failures, and stderr progress through the existing broker socket test. make build, explicit go build ./cmd/epithet, make test, and CLI help inspection passed.

---
# Log: 2026-09-07T16:53:31Z Brian McCallister

Closed.
