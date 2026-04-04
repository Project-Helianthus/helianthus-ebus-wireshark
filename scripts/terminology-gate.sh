#!/usr/bin/env bash
set -euo pipefail

if git grep -nIwiE 'm[a]ster|s[l]ave' -- . ':(exclude)LICENSE' ':(exclude)README.md'; then
  echo "Found legacy terminology."
  exit 1
fi

