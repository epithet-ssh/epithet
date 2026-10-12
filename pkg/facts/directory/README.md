# Directory facts and SCIM groups

The directory maps its source data into Writ's user and membership objects.
Users need an authentication ID. With SCIM, user `externalId` supplies that
identity; the SCIM user's server-issued `id` remains its provisioning key.
Inactive users are absent from the authorization lookup. Administration can
still inspect inactive users.

Each group membership contains the group's current display name and SCIM resource
ID. An optional group `externalId` is exposed as an additional attribute. Group
names need not be unique. `group:ops` matches members of any current group named
`ops`; `group{id:...}` follows one resource across renames. Renaming a group removes
its old name immediately. Deleting and recreating a group under the same name
makes name-based rules follow the replacement; ID-based rules do not follow it.

There are no historical group-name bindings. `epithet directory groups list`
shows current names and resource IDs; `epithet directory groups audit` retains
provisioning history and historical binding events. The bind command is removed.
Existing administrator group grants also match current names.

Static YAML supplies structured memberships without requiring group IDs:

```yaml
users:
  - id: oidc-subject
    userName: alice
    name: [alice, alice@example.com]
    attributes:
      department: engineering
      role: [developer, oncall]
    groups:
      - name: [operators]
        attributes:
          environment: production
```

Omitting `name` uses `userName` as the selectable name when present. An explicit
empty name collection supplies no selectable names. `userName` remains certificate
presentation, with ID fallback. Additional attributes must be strings, collections
of strings, or null, and cannot replace the defined `name` or `id` fields.

See the [fact API contract](../../../docs/fact-services.md) for the HTTP shape and
[Writ specification](../../../writ/SPEC.md) for matching rules.

## Database upgrade

The application creates new databases directly at schema version 2, without an
`aliases` table. It opens version 2 databases normally and rejects other schema
versions without upgrading them. `PRAGMA user_version` identifies the schema the
binary understands; the application does not manage migrations.

For the current single deployment, upgrades use disposable external tooling that
is not checked into this repository. The version 1 to 2 conversion checks the
source version, drops `aliases`, and advances the version in one transaction.
Resources, memberships, resource versions, directory revision identity, and audit
history remain intact, including historical binding events.

Stop the directory service and back up its database, including WAL state if
present, before running the external tool. Then start the new binary against the
converted database. Retain the backup for rollback; an older binary cannot open
schema version 2. Review policies and administrator grants that depended on
historical names, recompile Writ policies for IL schema 3, and update static group
entries to objects.

A supported migration framework, potentially Goose, is deferred in
[YATL gt3vjk35](../../../.tasks/open/gt3vjk35.md). No framework or automatic upgrade
path is introduced by this change.
