-- SPDX-License-Identifier: GPL-2.0-or-later

local plugin = {}

plugin.VERSION = "0.1.0"
plugin.LINKTYPE_USER0 = 147
plugin.WTAP_ENCAP_USER0 = 45
plugin.RECORD_VERSION = 1
plugin.RECORD_KIND_ENS_EVENT = 1
plugin.RECORD_KIND_EBUS_FRAME = 2

plugin.record_flags = {
  has_source = 0x01,
  request_like = 0x02,
  sync_terminated = 0x04,
}

local function band(a, b)
  if bit32 ~= nil then
    return bit32.band(a, b)
  end
  return a & b
end

local function lshift(a, b)
  if bit32 ~= nil then
    return bit32.lshift(a, b)
  end
  return a << b
end

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

function plugin.command_name(command)
  local names = {
    [0x00] = "resetted",
    [0x01] = "received",
    [0x02] = "started",
    [0x03] = "info",
    [0x0A] = "failed",
    [0x0B] = "error_ebus",
    [0x0C] = "error_host",
  }
  return names[command] or string.format("command_0x%02X", command)
end

function plugin.stream_kind_name(kind)
  if kind == plugin.RECORD_KIND_ENS_EVENT then
    return "ens-event"
  end
  if kind == plugin.RECORD_KIND_EBUS_FRAME then
    return "ebus-frame"
  end
  return string.format("unknown(%d)", kind)
end

function plugin.family_guess(opcode)
  if opcode >= 0xB500 and opcode <= 0xB5FF then
    return "vaillant-b5xx"
  end
  if opcode == 0 then
    return "unknown"
  end
  return "ebus-semantic"
end

function plugin.frame_type(flags, raw_len)
  if band(flags, plugin.record_flags.request_like) ~= 0 then
    return "request"
  end
  if raw_len == 1 then
    return "ack-nack"
  end
  return "response-or-broadcast"
end

if type(Proto) ~= "table" or type(ProtoField) ~= "table" then
  return plugin
end

local proto = Proto("helianthus_ebus", "Helianthus eBUS")

local fields = {
  magic = ProtoField.string("helianthus_ebus.magic", "Magic"),
  record_version = ProtoField.uint8("helianthus_ebus.record_version", "Record version", base.DEC),
  stream_kind = ProtoField.string("helianthus_ebus.stream_kind", "Stream kind"),
  command = ProtoField.uint8("helianthus_ebus.command", "ENS command", base.HEX),
  command_name = ProtoField.string("helianthus_ebus.command_name", "ENS command label"),
  flags = ProtoField.uint8("helianthus_ebus.flags", "Flags", base.HEX),
  has_source = ProtoField.bool("helianthus_ebus.has_source", "Has source", 8, nil, plugin.record_flags.has_source),
  request_like = ProtoField.bool("helianthus_ebus.request_like", "Request-like", 8, nil, plugin.record_flags.request_like),
  sync_terminated = ProtoField.bool("helianthus_ebus.sync_terminated", "Sync terminated", 8, nil, plugin.record_flags.sync_terminated),
  source = ProtoField.uint8("helianthus_ebus.source", "Initiator hint", base.HEX),
  qq = ProtoField.uint8("helianthus_ebus.qq", "QQ", base.HEX),
  zz = ProtoField.uint8("helianthus_ebus.zz", "ZZ", base.HEX),
  pb = ProtoField.uint8("helianthus_ebus.pb", "PB", base.HEX),
  sb = ProtoField.uint8("helianthus_ebus.sb", "SB", base.HEX),
  opcode = ProtoField.uint16("helianthus_ebus.opcode", "Opcode", base.HEX),
  opcode_label = ProtoField.string("helianthus_ebus.opcode_label", "Opcode label"),
  family = ProtoField.string("helianthus_ebus.family", "Family"),
  frame_type = ProtoField.string("helianthus_ebus.frame_type", "Frame type"),
  raw_length = ProtoField.uint16("helianthus_ebus.raw_length", "Raw length", base.DEC),
  payload = ProtoField.bytes("helianthus_ebus.payload", "Raw payload"),
}

proto.fields = fields

function proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "HLTH-EBUS"

  local subtree = tree:add(proto, buffer(), "Helianthus eBUS record")
  if buffer:len() == 0 then
    subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Empty Helianthus record")
    return
  end

  if buffer:len() < 14 then
    subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Record too short")
    return
  end

  local magic = buffer(0, 4):string()
  subtree:add(fields.magic, buffer(0, 4))
  if magic ~= "HLTH" then
    subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Magic mismatch")
    return
  end

  local version = buffer(4, 1):uint()
  local kind = buffer(5, 1):uint()
  local command = buffer(6, 1):uint()
  local flags = buffer(7, 1):uint()
  local source = buffer(8, 1):uint()
  local pb = buffer(9, 1):uint()
  local sb = buffer(10, 1):uint()
  local raw_length = buffer(12, 1):uint() + lshift(buffer(13, 1):uint(), 8)
  local payload_offset = 14

  subtree:add(fields.record_version, buffer(4, 1))
  subtree:add(fields.stream_kind, plugin.stream_kind_name(kind))
  subtree:add(fields.command, buffer(6, 1))
  subtree:add(fields.command_name, plugin.command_name(command))
  subtree:add(fields.flags, buffer(7, 1))
  subtree:add(fields.has_source, buffer(7, 1))
  subtree:add(fields.request_like, buffer(7, 1))
  subtree:add(fields.sync_terminated, buffer(7, 1))
  subtree:add(fields.raw_length, raw_length)

  if source ~= 0 or band(flags, plugin.record_flags.has_source) ~= 0 then
    subtree:add(fields.source, buffer(8, 1))
  end

  if version ~= plugin.RECORD_VERSION then
    subtree:add_expert_info(PI_PROTOCOL, PI_NOTE, "Unexpected record version")
  end

  if buffer:len() < payload_offset + raw_length then
    subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Record payload truncated")
    return
  end

  local raw_tvb = buffer(payload_offset, raw_length)
  subtree:add(fields.payload, raw_tvb)

  if kind == plugin.RECORD_KIND_ENS_EVENT then
    pinfo.cols.info = string.format("ENS %s data=0x%02X", plugin.command_name(command), raw_length > 0 and raw_tvb(0, 1):uint() or 0)
    return
  end

  if raw_length >= 1 then
    subtree:add(fields.qq, raw_tvb(0, 1))
  end
  if raw_length >= 2 then
    subtree:add(fields.zz, raw_tvb(1, 1))
  end
  subtree:add(fields.pb, buffer(9, 1))
  subtree:add(fields.sb, buffer(10, 1))
  local opcode = lshift(pb, 8) + sb
  subtree:add(fields.opcode, buffer(9, 2))
  subtree:add(fields.opcode_label, plugin.lookup_label(opcode))
  subtree:add(fields.family, plugin.family_guess(opcode))
  subtree:add(fields.frame_type, plugin.frame_type(flags, raw_length))

  local info = string.format(
    "%s opcode=0x%04X %s len=%d",
    plugin.frame_type(flags, raw_length),
    opcode,
    plugin.lookup_label(opcode),
    raw_length
  )
  if raw_length >= 2 then
    info = string.format("qq=0x%02X zz=0x%02X %s", raw_tvb(0, 1):uint(), raw_tvb(1, 1):uint(), info)
  end
  pinfo.cols.info = info
end

plugin.proto = proto
DissectorTable.get("wtap_encap"):add(plugin.WTAP_ENCAP_USER0, proto)
return plugin
