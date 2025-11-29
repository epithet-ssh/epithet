# macOS launchd service for epithet agent

This directory contains a launchd plist for running `epithet agent` as a background service on macOS.

## Prerequisites

1. Create your epithet config file at `~/.epithet/config`:
   ```
   match *.example.com
   ca-url https://ca.example.com
   auth epithet auth oidc --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID
   ```

2. Create the log directory:
   ```bash
   mkdir -p ~/.epithet/logs
   ```

3. Add epithet to your SSH config (`~/.ssh/config`):
   ```
   Include ~/.epithet/run/*/ssh-config.conf
   ```

## Installation

Copy the plist to your LaunchAgents directory:

```bash
cp contrib/macos/dev.epithet.epithet-agent.plist ~/Library/LaunchAgents/
```

**Intel Macs:** Edit the plist and change `/opt/homebrew/bin/epithet` to `/usr/local/bin/epithet`.

Load the service:

```bash
launchctl load ~/Library/LaunchAgents/dev.epithet.epithet-agent.plist
```

## Managing the service

Start:
```bash
launchctl start dev.epithet.epithet-agent
```

Stop:
```bash
launchctl stop dev.epithet.epithet-agent
```

Unload (disable):
```bash
launchctl unload ~/Library/LaunchAgents/dev.epithet.epithet-agent.plist
```

View logs:
```bash
tail -f ~/.epithet/logs/agent.log
tail -f ~/.epithet/logs/agent.err
```

## Troubleshooting

Check if the service is running:
```bash
launchctl list | grep epithet
```

If the service fails to start, check the error log at `~/.epithet/logs/agent.err`.
