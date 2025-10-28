#!/bin/bash
#
# Example bash auth plugin helper for epithet
#
# This demonstrates the fd 3 protocol for auth plugins.
#
# Protocol:
#   stdin (fd 0): Previous state blob (empty on first call)
#   stdout (fd 1): Authentication token (raw bytes)
#   stderr (fd 2): Error messages on failure
#   fd 3: New state blob to persist (max 10 MiB)
#   exit 0: success, non-zero: failure

# Example 1: Simple auth plugin that doesn't use state
auth_simple() {
    # Ignore stdin (no state management)
    cat > /dev/null

    # Perform authentication (e.g., browser flow, API call)
    token=$(curl -s "https://auth.example.com/login")

    # Output token to stdout
    echo -n "$token"

    # No state to persist (fd 3 not used)
}

# Example 2: Auth plugin with refresh token state
auth_with_refresh() {
    # Read previous state from stdin
    state=$(cat)

    if [ -z "$state" ]; then
        # Initial authentication - no prior state
        echo "Performing initial authentication..." >&2

        # Do full auth flow (browser, credentials, etc)
        access_token=$(do_full_auth)
        refresh_token=$(get_refresh_token)

        # Output access token to stdout
        echo -n "$access_token"

        # Save refresh token to fd 3 for next time
        echo -n "$refresh_token" >&3
    else
        # Refresh flow - use existing state
        echo "Refreshing token..." >&2

        # Use refresh token from state
        access_token=$(curl -s "https://auth.example.com/refresh" -d "$state")

        # Output new access token to stdout
        echo -n "$access_token"

        # Preserve state (or update if needed)
        echo -n "$state" >&3
    fi
}

# Example 3: Auth plugin with JSON state
auth_with_json_state() {
    state=$(cat)

    if [ -z "$state" ]; then
        # Initial auth
        access_token=$(do_full_auth)
        refresh_token=$(get_refresh_token)
        expires_at=$(date -u +%s -d '+8 hours')

        # Output token
        echo -n "$access_token"

        # Save JSON state to fd 3
        printf '{"refresh_token":"%s","expires_at":%d}' "$refresh_token" "$expires_at" >&3
    else
        # Extract refresh token from JSON state
        refresh_token=$(echo "$state" | jq -r '.refresh_token')

        # Refresh token
        access_token=$(curl -s "https://auth.example.com/refresh" \
                       -H "Authorization: Bearer $refresh_token")

        # Output new token
        echo -n "$access_token"

        # Update state with new expiry
        new_expires=$(date -u +%s -d '+8 hours')
        printf '{"refresh_token":"%s","expires_at":%d}' "$refresh_token" "$new_expires" >&3
    fi
}

# Example 4: Error handling
auth_with_error_handling() {
    state=$(cat)

    # Try to refresh
    if [ -n "$state" ]; then
        access_token=$(curl -s "https://auth.example.com/refresh" -d "$state")

        if [ $? -eq 0 ] && [ -n "$access_token" ]; then
            # Success
            echo -n "$access_token"
            echo -n "$state" >&3
            exit 0
        else
            # Refresh failed - report error and exit non-zero
            echo "Refresh token expired, please re-authenticate" >&2
            exit 1
        fi
    fi

    # Full auth flow
    access_token=$(do_full_auth)
    if [ $? -ne 0 ]; then
        echo "Authentication failed" >&2
        exit 1
    fi

    echo -n "$access_token"
}

# Note: These are examples only. Actual implementations would include:
# - Real authentication flows (OAuth, SAML, OIDC, etc.)
# - Proper error handling
# - Token expiry checks
# - Secure credential storage during auth flow
