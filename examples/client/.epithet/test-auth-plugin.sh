#!/bin/bash
# Simple test auth plugin - returns the shared secret for policy server authentication
#
# Usage:
#   Set EPITHET_POLICY_SECRET environment variable before running the broker:
#     export EPITHET_POLICY_SECRET=your-secret-here
#     epithet agent --auth ~/.epithet/test-auth-plugin.sh ...
#
# This secret must match the POLICY_SECRET configured in the policy server.

# Read state from stdin (ignore for this test)
cat > /dev/null

# Check if EPITHET_POLICY_SECRET is set
if [ -z "$EPITHET_POLICY_SECRET" ]; then
    echo "Error: EPITHET_POLICY_SECRET environment variable not set" >&2
    echo "Please set it with: export EPITHET_POLICY_SECRET=your-secret-here" >&2
    exit 1
fi

# Output the policy secret to stdout
echo -n "$EPITHET_POLICY_SECRET"

# Output empty state to fd 3 (no state needed for static secret)
echo -n "" >&3
