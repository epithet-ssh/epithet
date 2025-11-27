---
title: "When epithet cannot obtain certificate, fail the Match (return non-zero) and log clear error to stderr"
id: wc8kzhs1
created: 2025-10-25T19:51:28Z
updated: 2025-10-27T16:03:48Z
priority: critical
tags: [task]
---

When epithet cannot obtain a certificate (auth failures, CA errors, etc), the Match exec should: 1) Log clear, user-friendly error message to stderr explaining what went wrong (verbosity matching configured log level - helpful by default, more detail with -v flags), 2) Exit with non-zero status to fail the Match, 3) Allow SSH to fall through to subsequent Match blocks or default config. This enables breakglass/fallback scenarios where users have epithet Match blocks first, followed by special-case configs (e.g., breakglass@host with specific IdentityFile). Trade-off: May leak connection attempts to fallback systems, but this is acceptable to enable legitimate escape hatches.