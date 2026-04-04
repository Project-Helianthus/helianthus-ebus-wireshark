# AGENTS

This repository is part of the **Helianthus Multi-Protocol HVAC Gateway Platform**.

## Dual-AI Operating Model

All development follows the workspace-root
[`AGENTS.md`](../AGENTS.md).

## Repo-Specific Rules

1. The plugin must remain installable in an existing Wireshark build without
   recompilation.
2. The v1 semantic opcode catalog is locked unless the plan and docs change.
3. Unknown opcodes must fall back to raw display instead of speculative decode.
4. Any capture-format change must stay aligned with `helianthus-ebus-extcap`
   and `helianthus-docs-ebus`.

