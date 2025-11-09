#!/bin/bash
# Simple test auth plugin - prompts for shared secret and stores it in state
#
# This plugin demonstrates:
# - Interactive prompting for credentials (via macOS dialog on macOS)
# - Using EPITHET_POLICY_SECRET as initial default value
# - Storing credentials in state (kept in memory by broker)
# - Always prompting (allows user to correct wrong secret)
#
# The secret must match the POLICY_SECRET configured in the policy server.

# Read state from stdin
STATE=$(cat)

# Determine the default value for the dialog
if [ -n "$STATE" ]; then
    # If we have state, use it as the default
    DEFAULT_VALUE="$STATE"
else
    # Otherwise, use EPITHET_POLICY_SECRET env var as the default (if set)
    DEFAULT_VALUE="${EPITHET_POLICY_SECRET:-}"
fi

# Always prompt the user (even if we have state)
# This allows correcting a wrong secret
# On macOS, use osascript to show a dialog
if command -v osascript &> /dev/null; then
    SECRET=$(osascript -e "Tell application \"System Events\" to display dialog \"Enter your Epithet policy server shared secret:\" default answer \"$DEFAULT_VALUE\"" -e 'text returned of result' 2>&1)

    # Check if user cancelled (osascript returns error)
    if [ $? -ne 0 ]; then
        echo "Error: Authentication cancelled by user" >&2
        exit 1
    fi
else
    # Fallback: if no dialog available, use the default value directly
    if [ -z "$DEFAULT_VALUE" ]; then
        echo "Error: osascript not available and no default secret available" >&2
        echo "Please set EPITHET_POLICY_SECRET environment variable" >&2
        exit 1
    fi
    SECRET="$DEFAULT_VALUE"
fi

if [ -z "$SECRET" ]; then
    echo "Error: No secret provided" >&2
    exit 1
fi

# Output the secret to stdout (token for CA)
echo -n "$SECRET"

# Store the secret in state (fd 3) for next time as the default
echo -n "$SECRET" >&3
