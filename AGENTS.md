# AGENTS.md

## Purpose and boundaries

`helianthus-ebus-wireshark` is a passive Wireshark Lua dissector for ENS and
eBUS capture streams. It owns plugin code, the locked v1 opcode catalog,
semantic labels, display fields, and raw fallback behavior.

Keep the plugin installable in an existing Wireshark build without recompiling
Wireshark. Do not add live-capture transport, gateway semantic publishing, or
speculative protocol decoding. Unknown opcodes must fall back to raw display.

## Workflow

1. Reconcile `origin/main`, local changes, related issues, branches, PRs,
   reviews, and checks before work.
2. Use one scoped issue, a branch named `issue/<number>-<slug>` from current
   `main`, and one linked PR.
3. Keep changes narrow; add focused tests when behavior changes. Use RED-first
   evidence where practical for dissector, format, or protocol behavior.
4. Run `./scripts/ci_local.sh` before pushing. State the exact command and
   result in the PR, then obtain fresh review for the full PR head.
5. Do not merge without green applicable checks, resolved blocking findings,
   and any required public documentation. Stop at the requested boundary.

`ORCHESTRATOR` and `CO_PILOT` are portable reasoning roles. Use a co-pilot for
planning, bounded implementation, adversarial review, or a second opinion; do
not spend that role on routine reads, searches, polling, or shell inspection.
If it is unavailable, continue with an independent fresh review when the risk
justifies it.

## Safety, privacy, and documentation

The plugin is passive: do not introduce bus writes, capture-source control, or
active probing. Live capture, credentials, installation changes, and any action
that can affect a device require explicit operator confirmation at action time.
Never commit credentials, personal identifiers, network coordinates, device
fingerprints, or private/raw captures; use sanitized, minimal fixtures.

The v1 opcode catalog is locked unless its public contract changes with
test evidence. Capture-format changes must preserve compatibility with the
extcap producer or document the break. Put reusable eBUS contract documentation
in [`helianthus-docs-ebus`](https://github.com/Project-Helianthus/helianthus-docs-ebus);
keep only plugin-specific usage notes here.
