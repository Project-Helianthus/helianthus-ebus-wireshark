-- SPDX-License-Identifier: GPL-2.0-or-later

local plugin = {}

plugin.VERSION = "0.1.0"

plugin.semantic_ebus_opcodes = {
  [0x0304] = "eBUS semantic 0x0304",
  [0x0305] = "eBUS semantic 0x0305",
  [0x0306] = "eBUS semantic 0x0306",
  [0x0307] = "eBUS semantic 0x0307",
  [0x0308] = "eBUS semantic 0x0308",
  [0x0310] = "eBUS semantic 0x0310",
  [0x0500] = "eBUS semantic 0x0500",
  [0x0501] = "eBUS semantic 0x0501",
  [0x0502] = "eBUS semantic 0x0502",
  [0x0503] = "eBUS semantic 0x0503",
  [0x0504] = "eBUS semantic 0x0504",
  [0x0506] = "eBUS semantic 0x0506",
  [0x0507] = "eBUS semantic 0x0507",
  [0x0508] = "eBUS semantic 0x0508",
  [0x0509] = "eBUS semantic 0x0509",
  [0x050A] = "eBUS semantic 0x050A",
  [0x050B] = "eBUS semantic 0x050B",
  [0x050C] = "eBUS semantic 0x050C",
  [0x050D] = "eBUS semantic 0x050D",
  [0x0700] = "eBUS semantic 0x0700",
  [0x0701] = "eBUS semantic 0x0701",
  [0x0702] = "eBUS semantic 0x0702",
  [0x0703] = "eBUS semantic 0x0703",
  [0x0704] = "eBUS semantic 0x0704",
  [0x07FE] = "eBUS semantic 0x07FE",
  [0x07FF] = "eBUS semantic 0x07FF",
  [0x0800] = "eBUS semantic 0x0800",
  [0x0801] = "eBUS semantic 0x0801",
  [0x0802] = "eBUS semantic 0x0802",
  [0x0803] = "eBUS semantic 0x0803",
  [0x0804] = "eBUS semantic 0x0804",
  [0x0900] = "eBUS semantic 0x0900",
  [0x0901] = "eBUS semantic 0x0901",
  [0x0902] = "eBUS semantic 0x0902",
  [0x0903] = "eBUS semantic 0x0903",
  [0x0F01] = "eBUS semantic 0x0F01",
  [0x0F02] = "eBUS semantic 0x0F02",
  [0x0F03] = "eBUS semantic 0x0F03",
  [0xFE01] = "eBUS semantic 0xFE01",
  [0xFF00] = "eBUS semantic 0xFF00",
  [0xFF01] = "eBUS semantic 0xFF01",
  [0xFF02] = "eBUS semantic 0xFF02",
  [0xFF03] = "eBUS semantic 0xFF03",
  [0xFF04] = "eBUS semantic 0xFF04",
  [0xFF05] = "eBUS semantic 0xFF05",
  [0xFF06] = "eBUS semantic 0xFF06",
}

plugin.semantic_vaillant_opcodes = {
  [0xB504] = "Vaillant B504",
  [0xB505] = "Vaillant B505",
  [0xB506] = "Vaillant B506",
  [0xB509] = "Vaillant B509 boiler registers",
  [0xB510] = "Vaillant B510",
  [0xB511] = "Vaillant B511",
  [0xB512] = "Vaillant B512",
  [0xB516] = "Vaillant B516 energy",
  [0xB51A] = "Vaillant B51A",
  [0xB524] = "Vaillant B524 extended registers",
  [0xB555] = "Vaillant B555 timer protocol",
}

function plugin.lookup_label(opcode)
  return plugin.semantic_vaillant_opcodes[opcode]
    or plugin.semantic_ebus_opcodes[opcode]
    or string.format("Raw opcode 0x%04X", opcode)
end

function plugin.is_supported(opcode)
  return plugin.semantic_vaillant_opcodes[opcode] ~= nil
    or plugin.semantic_ebus_opcodes[opcode] ~= nil
end

if type(Proto) ~= "function" or type(ProtoField) ~= "table" then
  return plugin
end

local proto = Proto("helianthus_ebus", "Helianthus eBUS")

local fields = {
  record_version = ProtoField.uint8("helianthus_ebus.record_version", "Record version", base.DEC),
  stream_kind = ProtoField.string("helianthus_ebus.stream_kind", "Stream kind"),
  direction = ProtoField.string("helianthus_ebus.direction", "Direction"),
  pb = ProtoField.uint8("helianthus_ebus.pb", "PB", base.HEX),
  sb = ProtoField.uint8("helianthus_ebus.sb", "SB", base.HEX),
  opcode = ProtoField.uint16("helianthus_ebus.opcode", "Opcode", base.HEX),
  opcode_label = ProtoField.string("helianthus_ebus.opcode_label", "Opcode label"),
  payload = ProtoField.bytes("helianthus_ebus.payload", "Payload"),
}

proto.fields = fields

function proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "HLTH-EBUS"

  local subtree = tree:add(proto, buffer(), "Helianthus eBUS bootstrap record")
  if buffer:len() == 0 then
    subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Empty Helianthus record")
    return
  end

  local version = buffer(0, 1):uint()
  subtree:add(fields.record_version, buffer(0, 1))

  if buffer:len() < 5 then
    subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Bootstrap record too short")
    return
  end

  local pb = buffer(1, 1):uint()
  local sb = buffer(2, 1):uint()
  local opcode = bit32.lshift(pb, 8) + sb

  subtree:add(fields.pb, buffer(1, 1))
  subtree:add(fields.sb, buffer(2, 1))
  subtree:add(fields.opcode, buffer(1, 2))
  subtree:add(fields.opcode_label, plugin.lookup_label(opcode))
  subtree:add(fields.stream_kind, "bootstrap")
  subtree:add(fields.direction, "unknown")

  if buffer:len() > 3 then
    subtree:add(fields.payload, buffer(3))
  end

  if version ~= 1 then
    subtree:add_expert_info(PI_PROTOCOL, PI_NOTE, "Unexpected record version in bootstrap dissector")
  end
end

plugin.proto = proto
return plugin
