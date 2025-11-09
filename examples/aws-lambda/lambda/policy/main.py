"""
Epithet Policy Server - AWS Lambda implementation

This is a simple allow-all policy server for personal use.

For production, customize the policy logic in the handler() function below.
See docs/policy-server-api.yaml for the complete API specification.
"""

import json
import os
from typing import cast


def handler(event: dict[str, object], _context: object) -> dict[str, object]:
    """
    AWS Lambda handler for policy evaluation.

    Args:
        event: API Gateway event containing the policy request
        _context: Lambda context (unused)

    Returns:
        API Gateway response with policy decision
    """
    # Parse request body
    body_str = event.get("body", "{}")
    if not isinstance(body_str, str):
        body_str = "{}"

    try:
        body_obj: object = json.loads(body_str)
    except json.JSONDecodeError:
        return error_response(400, "Invalid JSON in request body")

    if not isinstance(body_obj, dict):
        return error_response(400, "Request body must be an object")

    # Extract request fields (typed after validation)
    body = cast(dict[str, object], body_obj)
    connection_obj = body.get("connection", {})

    if not isinstance(connection_obj, dict):
        return error_response(400, "connection must be an object")

    connection = cast(dict[str, object], connection_obj)

    # Log request (for debugging)
    if os.environ.get("LOG_LEVEL") == "debug":
        print(
            json.dumps(
                {
                    "event": "policy_request",
                    "remote_host": connection.get("remoteHost"),
                    "remote_user": connection.get("remoteUser"),
                }
            )
        )

    # TODO: Verify signature using CA public key (see docs/policy-server-api.yaml)
    # token = body.get('token', '')
    # signature = body.get('signature', '')

    # TODO: Validate authentication token (JWT, OIDC, etc.)
    # TODO: Check authorization (can this user access this host?)

    # Simple allow-all policy for personal use
    # Use the remote user as the principal - the certificate will authenticate
    # as the specific user requested in the SSH connection
    remote_user_obj = connection.get("remoteUser", "root")
    remote_user = remote_user_obj if isinstance(remote_user_obj, str) else "root"

    # Expiration in nanoseconds (5 minutes = 5 * 60 * 1e9 nanoseconds)
    expiration_ns = 5 * 60 * 1_000_000_000

    response: dict[str, object] = {
        "certParams": {
            "identity": "personal-user",
            "principals": [remote_user],
            "expiration": expiration_ns,
            "extensions": {
                "permit-pty": "",
                "permit-X11-forwarding": "",
                "permit-port-forwarding": "",
                "permit-user-rc": "",
            },
        },
        "policy": {
            "hostPattern": "*",
        },
    }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(response),
    }


def error_response(status_code: int, message: str) -> dict[str, object]:
    """Create an error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": message}),
    }
