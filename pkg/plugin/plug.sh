#!/usr/bin/env bash

out="$(echo $1 | base64 -D)"

echo "meow $out" >&2