#!/bin/bash
# Simple test auth plugin - just returns a static token
# In production, this would do real authentication

# Read state from stdin (ignore for this test)
cat > /dev/null

# Output a test token to stdout
echo -n "test-token-123"

# Output empty state to fd 3 (no state needed for test)
echo -n "" >&3
