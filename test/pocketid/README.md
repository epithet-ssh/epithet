# Pocket ID integration harness

`epithet_test.go.txt` runs Epithet's real HTTP adapter and SQLite store against
Pocket ID **v2.14.0** (release commit `5521266`). It uses Pocket ID's own database
fixtures and sync implementation, with an isolated local HTTP server and temporary
databases. It never contacts a deployed provider.

The fixture is kept outside Epithet's ordinary Go test packages because it imports
Pocket ID's internal packages. In a disposable checkout of that release:

```sh
# EPITHET_SOURCE is the absolute path to this Epithet checkout.
cp "$EPITHET_SOURCE/test/pocketid/epithet_test.go.txt" \
  backend/internal/scimsync/epithet_test.go
cd backend
go mod edit -replace "github.com/epithet-ssh/epithet=$EPITHET_SOURCE"
go mod edit -require github.com/epithet-ssh/epithet@v0.0.0
go test -mod=mod -tags unit ./internal/scimsync \
  -run '^TestEpithetProvisioningLifecycle$' -count=1
```

This deliberately modifies only the disposable upstream module. Pocket ID's test
harness has its own dependencies/toolchain requirements (including its SQLite
implementation); these are not Epithet dependencies or a CGO requirement for
Epithet. Pocket ID stores update timestamps at whole-second precision, so fixture
changes wait for a later second before updating the source record.

Covered: initial and repeated sync, provider ID correlation, server-issued member
IDs, name/profile changes, disable/reactivate, group rename, membership removal,
client assignment withdrawal/restoration, deletion/recreation, reserved policy
names and explicit rebinding, and remote listing/deletion across 1,003 users.
Epithet's regular tests additionally cover duplicate-name conflicts, conditional
writes, opaque extensions, audit rollback, concurrent snapshots, restart durability,
and OIDC → inventory → Writ → certificate issuance and administrator authorization.

Validated on macOS with Pocket ID v2.14.0. This is an isolated protocol integration
test, not a deployment or browser/UI test of a running Pocket ID instance.
