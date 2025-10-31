# Policy Server Lambda Function

Python implementation of an Epithet policy server for AWS Lambda.

## What it does

The policy server receives certificate requests from the CA and decides:

- Whether to approve the request
- Which usernames (principals) to allow
- How long the certificate should be valid
- Which SSH features to enable (pty, port forwarding, etc.)

## Default behavior

The default implementation is a **permissive allow-all policy for personal use**:

- Allows all users to access all hosts
- Grants the requested username as a principal
- Issues 5-minute certificates
- Enables all standard SSH extensions

**⚠️ This is NOT suitable for production or multi-user environments!**

## Customizing

Edit `main.py` and modify the `handler()` function. The TODO comments show where to add your logic:

```python
# TODO: Verify signature using CA public key
# TODO: Validate authentication token (JWT, OIDC, etc.)
# TODO: Check authorization (can this user access this host?)
```

### Example: Restrict by hostname

```python
remote_host = connection.get('remoteHost', '')

# Only allow access to *.example.com
if not remote_host.endswith('.example.com'):
    return error_response(403, f'Access to {remote_host} not allowed')
```

### Example: Restrict by user

```python
local_user = connection.get('localUser', '')

# Only allow specific users
allowed_users = ['alice', 'bob']
if local_user not in allowed_users:
    return error_response(403, f'User {local_user} not authorized')
```

### Example: Limit principals

```python
# Always use 'deploy' username, regardless of what was requested
response = {
    'certParams': {
        'identity': local_user,
        'principals': ['deploy'],  # Force specific username
        'expiration': '5m0s',
        'extensions': {'permit-pty': ''},
    },
    'policy': {'hostPattern': '*.example.com'},
}
```

## Security

**Signature verification**: The current implementation does not verify the CA signature. For production, you must verify the signature to prevent unauthorized certificate requests.

**Token validation**: The current implementation does not validate authentication tokens. For production, validate tokens from your auth plugin (JWT, OIDC, etc.).

## API Reference

See [docs/policy-server-api.yaml](../../../docs/policy-server-api.yaml) for the complete OpenAPI specification.

### Request format

```json
{
  "token": "authentication-token",
  "signature": "base64-ca-signature",
  "connection": {
    "localUser": "alice",
    "remoteHost": "server.example.com",
    "remoteUser": "deploy",
    "port": 22
  }
}
```

### Success response (200)

```json
{
  "certParams": {
    "identity": "alice",
    "principals": ["deploy"],
    "expiration": "5m0s",
    "extensions": {"permit-pty": ""}
  },
  "policy": {
    "hostPattern": "*.example.com"
  }
}
```

### Error response (403)

```json
{
  "error": "user not authorized"
}
```
