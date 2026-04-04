#!/usr/bin/env bash
set -euo pipefail

./scripts/terminology-gate.sh

lua_bin=""
for candidate in lua lua5.4 lua5.3 luajit; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    lua_bin="${candidate}"
    break
  fi
done

if [[ -z "${lua_bin}" ]]; then
  echo "SKIP: lua interpreter not found; CI remains authoritative for Lua validation"
  exit 0
fi

"${lua_bin}" ./scripts/check_opcode_catalog.lua
