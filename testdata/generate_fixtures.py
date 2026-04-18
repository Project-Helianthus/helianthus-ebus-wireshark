#!/usr/bin/env python3
"""Generate deterministic PCAP fixtures for the Helianthus eBUS dissector.

Outputs:
  testdata/hlth-ebus-edge-cases.pcap
  testdata/hlth-ens-and-kind-edge-cases.pcap

Run from the repository root:
  python3 testdata/generate_fixtures.py
"""

from __future__ import annotations

import pathlib
import struct

LINKTYPE_USER0 = 147
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
PCAP_SNAPLEN = 65535


def pcap_global_header() -> bytes:
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC,
        PCAP_VERSION[0],
        PCAP_VERSION[1],
        0,
        0,
        PCAP_SNAPLEN,
        LINKTYPE_USER0,
    )


def pcap_record(payload: bytes, ts_sec: int, ts_usec: int) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)) + payload


def build_pcap(records: list[bytes]) -> bytes:
    out = bytearray(pcap_global_header())
    for i, rec in enumerate(records):
        out += pcap_record(rec, 1700000000 + i, 0)
    return bytes(out)


def hex_to_bytes(spaced_hex: str) -> bytes:
    return bytes.fromhex(spaced_hex.replace(" ", "").replace("\n", ""))


# Fixture 1: eBUS frame edge cases.
ebus_records = [
    # Primary-Primary B524 (QQ=0x71, ZZ=0x10).
    hex_to_bytes("48 4C 54 48 01 02 00 04 00 B5 24 00 08 00 71 10 B5 24 01 02 D1 00"),
    # Primary-Secondary with reply, B524 (QQ=0x71, ZZ=0x15).
    hex_to_bytes(
        "48 4C 54 48 01 02 00 04 00 B5 24 00 0D 00 "
        "71 15 B5 24 01 02 D1 00 02 11 22 E3 00"
    ),
    # Broadcast (ZZ=0xFE) with opcode 0xFF06 and no ACK.
    hex_to_bytes("48 4C 54 48 01 02 00 04 00 FF 06 00 07 00 31 FE FF 06 01 00 D1"),
    # Invalid QQ=0xA9.
    hex_to_bytes("48 4C 54 48 01 02 00 04 00 B5 03 00 08 00 A9 08 B5 03 01 00 C1 00"),
    # Invalid ZZ=0xAA.
    hex_to_bytes("48 4C 54 48 01 02 00 04 00 B5 03 00 08 00 71 AA B5 03 01 00 C1 00"),
]

# Fixture 2: ENS + record-kind edge cases.
ens_records = [
    # ENS SEND, request_like=1, command=0x01, length=1 data=0x00.
    hex_to_bytes("48 4C 54 48 01 01 01 02 00 00 00 00 01 00 00"),
    # ENS RECEIVED, request_like=0, command=0x01, length=1 data=0x00.
    hex_to_bytes("48 4C 54 48 01 01 01 00 00 00 00 00 01 00 00"),
    # ENS RECEIVED, command=0x01, length=0 (no data).
    hex_to_bytes("48 4C 54 48 01 01 01 00 00 00 00 00 00 00"),
    # Unsupported kind=0, empty payload.
    hex_to_bytes("48 4C 54 48 01 00 00 00 00 00 00 00 00 00"),
    # Unsupported kind=3, plausible eBUS-looking payload.
    hex_to_bytes(
        "48 4C 54 48 01 03 00 00 00 B5 09 00 04 00 71 08 B5 09"
    ),
    # Unsupported kind=255, one-byte payload.
    hex_to_bytes("48 4C 54 48 01 FF 00 00 00 00 00 00 01 00 00"),
]


def main() -> None:
    here = pathlib.Path(__file__).resolve().parent
    (here / "hlth-ebus-edge-cases.pcap").write_bytes(build_pcap(ebus_records))
    (here / "hlth-ens-and-kind-edge-cases.pcap").write_bytes(build_pcap(ens_records))
    print("Wrote", here / "hlth-ebus-edge-cases.pcap")
    print("Wrote", here / "hlth-ens-and-kind-edge-cases.pcap")


if __name__ == "__main__":
    main()
