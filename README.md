# helianthus-ebus-wireshark

`helianthus-ebus-wireshark` is the Helianthus Wireshark plugin repository for
passive ENS and eBUS capture streams emitted by `helianthus-ebus-extcap`.

## Purpose and Scope

### What belongs in this repository

- Wireshark Lua dissector code.
- Opcode catalog and semantic labels for the locked v1 scope.
- Wireshark display helpers such as field registration and fallback raw decode.
- Local smoke and syntax checks for plugin bootstrap.

### What does not belong in this repository

- Live capture transport code.
- Gateway semantic publishing logic.
- Protocol documentation ownership beyond plugin-specific usage notes.

## Status

- Bootstrap repository.
- Lua plugin scaffold exists and carries the v1 opcode catalog.
- Live dissector integration against real `pcapng` captures is pending.
- Licensing follows the Wireshark lane: `GPL-2.0-or-later`.

## Quickstart

### Validate repository

```bash
./scripts/ci_local.sh
```

### Load opcode catalog in plain Lua

```bash
lua scripts/check_opcode_catalog.lua
```

### Install locally in Wireshark

Copy `dissectors/helianthus-ebus.lua` into your personal Wireshark plugins
directory.

## Locked V1 Semantic Scope

- 46 generic eBUS semantic opcodes.
- 11 Vaillant `0xB5xx` semantic opcodes.
- Unknown opcodes fall back to raw display.
