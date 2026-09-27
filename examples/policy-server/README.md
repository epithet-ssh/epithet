# Writ deployment example

Copy `policy.example.writ` to `policy.writ` and `inventory.example.yaml` to
`inventory.yaml`. Edit the users, hosts, and access rules for your deployment.

Create distinct persistent CA and control keys:

```sh
ssh-keygen -t ed25519 -f ca_key -N '' -C epithet-ca
ssh-keygen -t ed25519 -f control_key -N '' -C epithet-control
```

Configure the combined launcher in `server.yaml`:

```yaml
server:
  ca-key: ./ca_key
  control-key: ./control_key
  listen: 127.0.0.1:8080
ca:
  policy-file: ./policy.writ
  oidc:
    issuer: https://accounts.google.com
    client-id: your-client-id
directory:
  static: [./inventory.yaml]
inventory:
  static: [./inventory.yaml]
  principal-mode: account-name
control:
  directory-admin-group: [directory-operators]
  inventory-admin-group: [host-operators]
```

This example explicitly uses account-name principals. For destination binding,
use `epithet-principal-v1` and configure host domains as described in the
[principal guide](../../docs/principals.md).

Validate and run:

```sh
epithet policy --check --policy-file policy.writ
epithet --config server.yaml directory --check
epithet --config server.yaml inventory --check
epithet --config server.yaml server
```

The launcher supervises separate CA, control, directory, inventory, and router
processes. Writ evaluates inside CA. Put TLS termination in front of the public
router and give agents the HTTPS CA URL. Control's public management route is
advertised by CA; private backend sockets are never exposed to clients.

See the [deployment guide](../../docs/inventory.md) for independent supervision,
[Writ guide](../../docs/policy-server.md) for rules, and
[fact provider API](../../docs/fact-services.md) for bespoke integrations.
