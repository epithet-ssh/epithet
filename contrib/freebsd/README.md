# FreeBSD package repository

Epithet publishes a native package for `FreeBSD:15:amd64` at
`https://pkg.epithet.dev`. The repository is built and signed on a dedicated
FreeBSD build host; a Bastille jail serves the completed repository over
HTTPS.

The package is intentionally host-focused. It installs only
`/usr/local/bin/epithet`, supports `epithet host enroll`, and does not install
or enable a persistent service. Enrollment state under `/var/db/epithet` and
the managed sshd configuration are not package-owned, so upgrades and package
deletion leave them in place.

## Client setup

Bootstrap the repository public key and configuration:

```sh
install -d -m 0755 /usr/local/etc/pkg/keys /usr/local/etc/pkg/repos
fetch -o /usr/local/etc/pkg/keys/epithet.pub \
  https://pkg.epithet.dev/keys/epithet.pub
fetch -o /usr/local/etc/pkg/repos/Epithet.conf \
  https://pkg.epithet.dev/Epithet.conf
pkg update -r Epithet
pkg install -r Epithet epithet
```

Normal upgrades use:

```sh
pkg upgrade epithet
```

The checked-in [`ops/Epithet.conf`](ops/Epithet.conf) expands `${ABI}` on the
client and requires repository metadata signed by the bootstrapped public key.

## Architecture

- Poudriere runs on the build host against a `15.1-RELEASE` amd64 build jail and a local
  ports tree containing [`port`](port/). The publisher signs the final
  Epithet-only repository on the host after the clean poudriere build. Build
  dependencies come from FreeBSD's signed `latest` package repository; Epithet
  itself is always built from the local port in the clean jail.
- `/usr/local/etc/ssl/keys/epithet-pkg.key` is root-readable only and never
  enters the serving jail.
- The publisher extracts only the Epithet package from poudriere output,
  creates signed repository metadata, tests the candidate, and then moves a
  `latest` symlink to the retained release directory.
- The `pkg` Bastille jail has a read-only nullfs mount of
  `/srv/epithet-pkg` and runs only Caddy.
- A failed build or test cannot alter `latest`. Each successful release remains
  under `FreeBSD:15:amd64/releases/` for explicit rollback.

## Build-host bootstrap

Install build tools and initialize poudriere:

```sh
pkg install poudriere git
install -d -m 0755 /usr/ports/distfiles
install -d -m 0700 /usr/local/etc/ssl/keys
openssl genrsa -out /usr/local/etc/ssl/keys/epithet-pkg.key 4096
chmod 0400 /usr/local/etc/ssl/keys/epithet-pkg.key

poudriere jail -c -j 151amd64 -v 15.1-RELEASE -a amd64
poudriere ports -c -p epithet -m git+https -B main
```

Keep an encrypted offline backup of the private key. Losing it prevents new
publication; disclosure requires distributing a new public key to clients
before changing the repository signer.

Install the files under [`ops`](ops/) as follows:

| Source | Build-host destination |
|---|---|
| `port/` | `/usr/local/share/epithet-pkg/port/` |
| `ops/epithet-pkg-publish` | `/usr/local/sbin/epithet-pkg-publish` |
| `ops/epithet-pkg-test` | `/usr/local/sbin/epithet-pkg-test` |
| `ops/epithet-pkg.conf.sample` | `/usr/local/etc/epithet-pkg.conf` |
| `ops/poudriere.conf` | `/usr/local/etc/poudriere.d/poudriere.conf` |

Create `/srv/epithet-pkg` as a dedicated ZFS dataset. The serving jail is a
thin VNET jail on the existing `bridge0` network:

```sh
bastille create -B pkg 15.1-RELEASE PKG_JAIL_IP/CIDR bridge0
bastille mount pkg /srv/epithet-pkg /srv/pkg nullfs ro 0 0
bastille pkg pkg install caddy
```

The jail must use a DNS resolver reachable from its VNET interface.

Install [`ops/Caddyfile`](ops/Caddyfile) at
`/usr/local/etc/caddy/Caddyfile` inside the jail, enable Caddy, and start it
after the `pkg.epithet.dev` A record points at the jail's address:

```sh
bastille sysrc pkg caddy_enable=YES
bastille service pkg caddy start
```

## Publishing

Publication is deliberately explicit:

```sh
sudo epithet-pkg-publish publish v0.23.0
sudo epithet-pkg-publish status
```

The command validates the tag, builds the preceding stable version when it is
not already retained, runs poudriere's port tests, builds the current package,
generates signed candidate metadata, and exercises fresh install, upgrade,
deinstall, version, and host-state preservation checks. Only then does it move
the public `latest` symlink.

The command is idempotent for the currently published version. A future poller
may discover the latest stable GitHub tag and invoke this same command; it must
not implement a separate publication path.

## Rollback and recovery

List retained versions and select one atomically:

```sh
find /srv/epithet-pkg/FreeBSD:15:amd64/releases -mindepth 1 -maxdepth 1 -type d
sudo epithet-pkg-publish rollback 0.22.0
```

Rollback changes repository metadata for subsequent client updates. It cannot
recall a package already downloaded or installed; affected hosts must run
`pkg update -f -r Epithet` followed by an explicit downgrade if required.

Before deleting an old release directory, confirm that it is neither the
`latest` target nor needed for rollback. Repository signing-key rotation is a
separate, staged operation: distribute the new public key and client
configuration first, verify adoption, then change the signer.
