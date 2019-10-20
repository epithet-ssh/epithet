#!/usr/bin/env bash

out="$(echo $1 | base64 -D)"

echo "OH NO!" >&2

exit 1