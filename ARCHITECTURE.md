# Architecture

## Goal

`helianthus-ebus-wireshark` provides Lua dissectors for Helianthus passive
capture records.

## Current Bootstrap Layout

- `dissectors/helianthus-ebus.lua`: bootstrap plugin and opcode catalog.
- `scripts/check_opcode_catalog.lua`: plain-Lua validation helper.
- `scripts/ci_local.sh`: local validation wrapper.

## Planned Decode Layers

1. ENS transport/control events.
2. eBUS frame metadata and fallback raw payload view.
3. Semantic opcode decode for the locked v1 catalog.

## Invariants

- Installable without recompiling Wireshark.
- Unknown opcodes fall back to raw display.
- `B524` and `B555` remain distinct semantic families.

