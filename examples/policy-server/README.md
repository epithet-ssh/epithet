# Writ deployment example

Copy `policy.example.writ` to `policy.writ` and `inventory.example.yaml` to
`yaml`. Edit the users, hosts, and access rules for your deployment.

Create distinct persistent CA and control keys:

```sh
ssh-keygen -t ed25519 -f ca_key -N '' -C epithet-ca
ssh-keygen -t ed25519 -f control_key -N '' -C epithet-control
```

Configure the combined launcher in `toml`:

```toml
ca-key-file = "./ca_key"
control-key-file = "./control_key"
directory-admin-group = ["directory-operators"]
directory-static-file = ["./inventory.yaml"]
inventory-admin-group = ["host-operators"]
inventory-static-file = ["./inventory.yaml"]
listen = "127.0.0.1:8080"
oidc-client-id = "your-client-id"
oidc-issuer = "https://accounts.google.com"
policy-file = "./policy.writ"
principal-mode = "account-name"
```

This example explicitly uses account-name principals. For destination binding,
use `epithet-principal-v1` and configure host domains as described in the
[principal guide](../../docs/principals.md).

Validate and run:

```sh
epithet policy --check --policy-file policy.writ
epithet --config server.toml directory --check
epithet --config server.toml inventory --check
epithet --config server.toml server
```

The launcher supervises separate CA, control, directory, inventory, and router
processes. Writ evaluates inside CA. Put TLS termination in front of the public
router and give agents the HTTPS CA URL. Control's public management route is
advertised by CA; private backend sockets are never exposed to clients.

See the [deployment guide](../../docs/inventory.md) for independent supervision,
[Writ guide](../../docs/policy-server.md) for rules, and
[fact provider API](../../docs/fact-services.md) for bespoke integrations.
