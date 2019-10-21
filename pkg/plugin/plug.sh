#!/usr/bin/env bash

in="$(echo $1 | base64 -D)"

echo "meow $in" >&2