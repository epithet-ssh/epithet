---
yatl_version: 1
title: Prepare FreeBSD SCIM state directory with service ownership
id: ts3dqavm
created: 2026-09-19T00:07:02.780773Z
updated: 2026-09-29T02:31:19.411744Z
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

---
# Log: 2026-09-29T02:31:19Z Brian McCallister

Completed native validation on hati using disposable Bastille jail epithet-state-test (FreeBSD 15.1) and the actual published epithet-0.39.1 package. Fresh install: both standalone directory/inventory rc.d services and the combined server created /var/db/epithet/directory and inventory as epithet:epithet mode 0700; the fresh parent was root:wheel 0755. Real services ran under epithet, the combined CA endpoint responded, and directory --check plus inventory --check passed via su -m epithet. Upgrade: installed 0.38.1, then used a disposable local pkg repository to upgrade to 0.39.1. SHA256 comparisons preserved the existing SQLite database, directory/inventory fixture data, unrelated root-owned state, and operator-edited TOML configs through the package upgrade and both startup modes. Existing root:wheel parent mode 0751 and unrelated file mode 0600 remained unchanged. Repeated both --check commands as epithet after the upgrade. No production service or repository was changed; published versions remained 0.39.1. Destroyed the test jail and verified its files, running jail, loopback alias, and temporary builder fixture were removed. Local transcripts: /tmp/epithet-state-test-fresh.log and /tmp/epithet-state-test-upgrade.log.

---
# Log: 2026-09-29T02:31:19Z Brian McCallister

Closed: Implemented and deployed previously; native fresh-install, package-upgrade, state-preservation, actual ownership, combined/standalone startup, and service-account checks now pass. Disposable jail cleaned up.
