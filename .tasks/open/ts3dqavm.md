---
yatl_version: 1
title: Prepare FreeBSD SCIM state directory with service ownership
id: ts3dqavm
created: 2026-09-19T00:07:02.780773Z
updated: 2026-09-29T01:38:35.294097Z
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

---
# Log: 2026-09-29T01:28:03Z Brian McCallister

Implemented default-state preparation in the FreeBSD server, directory, and inventory rc.d hooks in the sibling epithet-packaging checkout. The current topology gives SCIM to directory (not inventory). Hooks create only their directory/ and inventory/ subdirectories with service-account ownership and mode 0700, preserving an existing shared parent and stored data. Local startup-hook tests cover preparation, preservation, conflicts, and preparation failures; packaging make test passes (20 tests). Native FreeBSD install/upgrade and service-account --check validation remain outstanding; leave this task open.

---
# Log: 2026-09-29T01:38:35Z Brian McCallister

Deployed the reviewed packaging snapshot to the pkgbuild jail on hati and restored its existing source-tag polling schedule. All 20 packaging regression tests pass on the actual FreeBSD builder, and the ports framework resolves the five updated rc.d services. These tests still simulate startup ownership effects; native package install/upgrade and checks as the epithet service account against the TOML-capable source release remain outstanding.
