---
yatl_version: 1
title: Prepare FreeBSD SCIM state directory with service ownership
id: ts3dqavm
created: 2026-09-19T00:07:02.780773Z
updated: 2026-09-19T00:24:07.059066Z
author: Brian McCallister
priority: high
tags:
- packaging
- freebsd
- scim
---

Deferred follow-up from the FreeBSD 0.34.2 to 0.35.1 SCIM deployment. Running inventory --check as epithet with state-dir /var/db/epithet failed: mkdir /var/db/epithet/directory: permission denied. Creating that directory as epithet:epithet with mode 0700 resolved the failure. Update epithet-packaging FreeBSD packaging so fresh installations and upgrades prepare the default SCIM state directory without a manual root command. Keep the shared state parent and unrelated files under their existing ownership; preserve existing inventory and directory data. Check both combined-server and standalone-inventory operation. Validate install and upgrade in a FreeBSD jail and run inventory --check as the service account. Packaging source is in epithet-packaging/freebsd/port; current rc.d scripts only create runtime and log directories.

---
# Log: 2026-09-19T00:07:02Z Brian McCallister

Created task.

---
# Log: 2026-09-19T00:24:07Z Brian McCallister

The user also selected managed host inventory as the default. Packaging preparation must cover the inventory/ state directory as well as directory/ for SCIM, with service-account ownership and preservation of existing data.
