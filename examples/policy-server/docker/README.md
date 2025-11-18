# Docker Deployment

This directory contains Docker and Docker Compose configurations for running epithet CA and policy server.

## Quick Start

### 1. Build the Image

From the repository root:

```bash
docker build -t epithet:latest -f examples/policy-server/docker/Dockerfile .
```

### 2. Prepare Configuration

```bash
cd examples/policy-server/docker

# Create config directory
mkdir -p config

# Generate CA key
ssh-keygen -t ed25519 -f config/ca_key -N "" -C "epithet-ca"

# Copy and edit policy configuration
cp ../policy.example.yaml config/policy.yaml
editor config/policy.yaml
```

Update `config/policy.yaml`:
- Set `ca_public_key` to contents of `config/ca_key.pub`
- Configure your OIDC provider
- Add your users

### 3. Start Services

```bash
docker-compose up -d
```

### 4. Verify Services

```bash
# Check status
docker-compose ps

# Check logs
docker-compose logs -f

# Test CA endpoint
curl http://localhost:8080/

# Test policy endpoint (should return error without proper request)
curl -X POST http://localhost:9999/
```

## Configuration Files

Place these in the `config/` directory:

- `ca_key` - CA private key (generate with ssh-keygen)
- `ca_key.pub` - CA public key (auto-generated)
- `policy.yaml` - Policy configuration

## Production Considerations

### Security

1. **Protect the CA private key:**
   ```bash
   chmod 600 config/ca_key
   ```

2. **Use Docker secrets for sensitive data:**
   ```yaml
   secrets:
     ca_key:
       file: ./config/ca_key
     policy_config:
       file: ./config/policy.yaml
   ```

3. **Run with read-only root filesystem:**
   ```yaml
   services:
     policy:
       read_only: true
   ```

### TLS/HTTPS

Use a reverse proxy (nginx, Traefik) for TLS termination:

```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
```

### Resource Limits

Add resource constraints:

```yaml
services:
  policy:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.25'
          memory: 128M
```

### High Availability

Run multiple policy server instances:

```yaml
services:
  policy:
    deploy:
      replicas: 3
```

Add a load balancer:

```yaml
services:
  haproxy:
    image: haproxy:alpine
    ports:
      - "9999:9999"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
```

## Monitoring

### Health Checks

The compose file includes health checks. Monitor with:

```bash
docker-compose ps
```

### Logs

```bash
# All logs
docker-compose logs -f

# Specific service
docker-compose logs -f policy
docker-compose logs -f ca

# Since timestamp
docker-compose logs --since 2024-01-01T12:00:00
```

### Metrics

Consider adding Prometheus exporter:

```yaml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
```

## Troubleshooting

### Policy server won't start

```bash
# Check logs
docker-compose logs policy

# Verify config file
docker-compose exec policy cat /config/policy.yaml

# Check file permissions
ls -la config/
```

### CA can't reach policy server

```bash
# Check network connectivity
docker-compose exec ca ping policy

# Verify policy server is listening
docker-compose exec policy netstat -ln | grep 9999
```

### Services keep restarting

```bash
# Check health check status
docker inspect epithet-policy | jq '.[0].State.Health'

# Disable health checks temporarily
docker-compose up -d --no-deps policy
```

## Updating

### Update Configuration

```bash
# Edit config
editor config/policy.yaml

# Reload policy server (will re-read config)
docker-compose restart policy
```

### Update Image

```bash
# Rebuild image
docker build -t epithet:latest -f examples/policy-server/docker/Dockerfile .

# Recreate containers
docker-compose up -d --force-recreate
```

## Cleanup

```bash
# Stop services
docker-compose down

# Remove volumes
docker-compose down -v

# Remove images
docker rmi epithet:latest
```
