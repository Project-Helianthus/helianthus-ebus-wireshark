#!/usr/bin/env bash
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${here}/.." && pwd)"
cd "${repo_root}"

echo "[integration] $(tshark --version 2>/dev/null | head -1 || echo 'tshark not found')"

if ! command -v tshark >/dev/null 2>&1; then
  if [[ "${CI:-}" == "true" || "${TSHARK_REQUIRED:-0}" == "1" ]]; then
    echo "FAIL: tshark not found in PATH; CI must install wireshark-common before running integration tests" >&2
    exit 1
  fi
  echo "SKIP: tshark not found in PATH; install wireshark-common to run dissector integration tests"
  exit 0
fi

work_dir="$(mktemp -d -t helianthus-ebus-ws.XXXXXX)"
trap 'rm -rf "${work_dir}"' EXIT

# Use an isolated HOME so any personal wireshark plugin does not shadow the
# working-copy dissector under test.
export HOME="${work_dir}"
plugin_dir="${work_dir}/.local/lib/wireshark/plugins"
mkdir -p "${plugin_dir}"
cp dissectors/helianthus-ebus.lua "${plugin_dir}/"

fixture_dir="testdata"
if [[ ! -s "${fixture_dir}/hlth-ebus-edge-cases.pcap" ]] \
  || [[ ! -s "${fixture_dir}/hlth-ens-and-kind-edge-cases.pcap" ]]; then
  echo "Fixtures missing; regenerating from testdata/generate_fixtures.py"
  python3 "${fixture_dir}/generate_fixtures.py"
fi

# user_dlts routes LINKTYPE_USER0 (DLT=147) through the helianthus_ebus
# dissector even on fresh Wireshark installs (e.g. CI) that ship without a
# preconfigured user_dlts UAT entry.
user_dlts_pref='uat:user_dlts:"User 0 (DLT=147)","helianthus_ebus","0","","0",""'

run_tshark_tree() {
  local fixture="$1"
  local stderr_file
  stderr_file="$(mktemp)"
  local out
  if ! out="$(tshark -r "${fixture}" -O helianthus_ebus -o "${user_dlts_pref}" 2>"${stderr_file}")"; then
    echo "tshark failed on ${fixture}; stderr:" >&2
    cat "${stderr_file}" >&2
    rm -f "${stderr_file}"
    return 1
  fi
  rm -f "${stderr_file}"
  printf '%s' "${out}"
}

run_tshark_info() {
  local fixture="$1"
  tshark -r "${fixture}" -T fields -e _ws.col.Info -o "${user_dlts_pref}" 2>/dev/null
}

expect_match() {
  local label="$1"
  local haystack="$2"
  local needle="$3"
  if ! grep -Fq -- "${needle}" <<<"${haystack}"; then
    echo "FAIL: ${label}: expected to find '${needle}'" >&2
    echo "---- captured output ----" >&2
    printf '%s\n' "${haystack}" >&2
    echo "-------------------------" >&2
    exit 1
  fi
}

expect_no_match() {
  local label="$1"
  local haystack="$2"
  local needle="$3"
  if grep -Fq -- "${needle}" <<<"${haystack}"; then
    echo "FAIL: ${label}: did not expect to find '${needle}'" >&2
    echo "---- captured output ----" >&2
    printf '%s\n' "${haystack}" >&2
    echo "-------------------------" >&2
    exit 1
  fi
}

ebus_tree="$(run_tshark_tree "${fixture_dir}/hlth-ebus-edge-cases.pcap")"
# WS12: legacy terminology must be gone from decoded output. The forbidden
# words are built at runtime from split literals so scripts/terminology-gate.sh
# (word-boundary match, case insensitive) does not flag this file itself.
legacy_primary_primary="Mas""ter-Mas""ter"
legacy_primary_secondary="Mas""ter-Sla""ve"
expect_no_match "WS12 ebus output clean of legacy terms" "${ebus_tree}" "${legacy_primary_primary}"
expect_no_match "WS12 ebus output clean of legacy terms" "${ebus_tree}" "${legacy_primary_secondary}"
# WS15: structured request/reply on primary-secondary and broadcast.
expect_match "WS15 primary-primary decoded" "${ebus_tree}" "Frame type: Primary-Primary"
expect_match "WS15 primary-secondary decoded" "${ebus_tree}" "Frame type: Primary-Secondary"
expect_match "WS15 broadcast decoded" "${ebus_tree}" "Frame type: Broadcast"
expect_match "WS15 request subtree" "${ebus_tree}" "Request (len="
expect_match "WS15 reply subtree" "${ebus_tree}" "Reply (len="
# WS17: invalid addresses flagged.
expect_match "WS17 invalid address" "${ebus_tree}" "Frame type: Invalid"
# WS18: manufacturer family for FF06.
expect_match "WS18 manufacturer family" "${ebus_tree}" "Family: ebus-manufacturer"
# WS20: reserved byte 11 surfaced.
expect_match "WS20 reserved byte exposed" "${ebus_tree}" "Reserved (byte 11)"
# WS22: no spurious "resetted" label on eBUS records (ENS command label
#       field must not appear for kind=RECORD_KIND_EBUS_FRAME).
expect_no_match "WS22 no resetted leak on ebus frames" "${ebus_tree}" "ENS command label"
# WS25: new Vaillant label (B503 used in invalid-address fixtures).
expect_match "WS25 B503 label" "${ebus_tree}" "Vaillant B503"
# WS15 + WS20 + WS26 supplementary coverage from the expanded fixture set.
expect_match "WS15 primary-secondary NAK exposes Reply: <none>" "${ebus_tree}" "Reply: <none>"
expect_match "WS20 reserved byte non-zero surfaced" "${ebus_tree}" "Reserved (byte 11): 0xff"
expect_match "WS15 truncated payload expert warning" "${ebus_tree}" "Record payload truncated"
expect_match "WS26 source field rendered when has_source flag set" "${ebus_tree}" "Initiator hint: 0x71"

ens_tree="$(run_tshark_tree "${fixture_dir}/hlth-ens-and-kind-edge-cases.pcap")"
ens_info="$(run_tshark_info "${fixture_dir}/hlth-ens-and-kind-edge-cases.pcap")"
# WS13: direction-aware ENS label (tree + info column).
expect_match "WS13 ENS send tree label" "${ens_tree}" "ENS command label: send"
expect_match "WS13 ENS received tree label" "${ens_tree}" "ENS command label: received"
expect_match "WS13 ENS send in info column" "${ens_info}" "ENS send"
expect_match "WS13 ENS received in info column" "${ens_info}" "ENS received"
# WS16: empty-payload "no data" phrasing in info column.
expect_match "WS16 empty payload phrasing" "${ens_info}" "no data"
expect_match "WS16 non-empty payload still rendered" "${ens_info}" "data=0x00"
# WS24: unsupported kinds reported in info column and expert warning in tree.
expect_match "WS24 unsupported kind info" "${ens_info}" "Unsupported record kind="

echo "PASS: dissector integration tests"
