# FreeBSD package for epithet

Build a FreeBSD `.pkg` for epithet and run it as a service via rc.d.

## Building the package

Requires Go (`pkg install go`).

```sh
cd contrib/freebsd
make package
```

To set a specific version:

```sh
make package VERSION=0.12.0
```

This builds epithet from source, stages the files, and creates `epithet-<version>.pkg`.

## Installing

```sh
pkg add ./epithet-*.pkg
```

## Server setup

1. Generate a CA key:
   ```sh
   ssh-keygen -t ed25519 -f /usr/local/etc/epithet/ca.key -N ""
   ```

2. Copy and edit the sample config:
   ```sh
   cp /usr/local/etc/epithet/server.yaml.sample /usr/local/etc/epithet/server.yaml
   vi /usr/local/etc/epithet/server.yaml
   ```

3. Set CA key ownership (the `epithet` user is created automatically during install):
   ```sh
   chown epithet /usr/local/etc/epithet/ca.key
   ```

4. Enable and start:
   ```sh
   sysrc epithet_server_enable=YES
   service epithet_server start
   ```

## rc.conf tunables

| Variable | Default | Description |
|---|---|---|
| `epithet_server_enable` | `NO` | Enable the server service |
| `epithet_server_config` | `/usr/local/etc/epithet/server.yaml` | Config file path |
| `epithet_server_user` | `epithet` | User to run as |
| `epithet_server_cakey` | `/usr/local/etc/epithet/ca.key` | CA private key path |
| `epithet_server_listen` | `127.0.0.1:8080` | Listen address |
| `epithet_server_logfile` | `/var/log/epithet_server.log` | Log file path |

## Troubleshooting

Check if the service is running:
```sh
service epithet_server status
```

View logs:
```sh
tail -f /var/log/epithet_server.log
```
