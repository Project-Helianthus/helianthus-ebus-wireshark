# Dissector test fixtures

Two synthetic PCAP files exercise the Helianthus eBUS dissector end-to-end
via `scripts/dissector_integration_test.sh`.

| File | Records |
| --- | --- |
| `hlth-ebus-edge-cases.pcap` | primary-primary B524, primary-secondary B524 with reply, broadcast FF06 (DST=0xFE), invalid QQ=0xA9, invalid ZZ=0xAA |
| `hlth-ens-and-kind-edge-cases.pcap` | ENS send (request_like=1, data=0x00), ENS received (data=0x00), ENS received with no data, unsupported record kinds 0/3/255 |

Both fixtures use link-type `USER0` (147) and the HLTH record layout defined
in `helianthus-ebus-extcap`. They are generated deterministically from
`testdata/generate_fixtures.py` so regenerating them after editing the
script yields byte-identical output.

## Regenerate

```
python3 testdata/generate_fixtures.py
```

## Cross-references

- `WS19` in `_work_adaptermux_audit/FINAL-CONSOLIDATED-AUDIT-REPORT.md`
  (empty testdata, no integration coverage).
- `WS23` — ENS records are not produced by `helianthus-ebus-extcap` today
  (`internal/capture/live.go` folds ens-events/both streams into
  `StreamEbusFrames`); the ENS-side fixtures keep that code path under test
  until the extcap writer starts emitting `RECORD_KIND_ENS_EVENT` records.
