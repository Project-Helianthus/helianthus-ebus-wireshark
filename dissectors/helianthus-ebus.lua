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

function plugin.transaction_type(zz)
  if zz == 0xFE then
    return "Broadcast"
  end
  local function initiator_part(bits)
    return bits == 0x0 or bits == 0x1 or bits == 0x3 or bits == 0x7 or bits == 0xF
  end
  if initiator_part(zz & 0x0F) and initiator_part((zz >> 4) & 0x0F) then
    return "Primary-Primary"
  end
  return "Primary-Secondary"
end

function plugin.parse_primary_secondary_segments(raw_tvb)
  local raw_length = raw_tvb:len()
  if raw_length < 7 then
    return nil, "primary-secondary transaction too short"
  end

  local request_length = raw_tvb(4, 1):uint()
  local request_crc_offset = 5 + request_length
  local request_ack_offset = request_crc_offset + 1
  if request_ack_offset >= raw_length then
    return nil, "request segment truncated"
  end

  local request = {
    offset = 0,
    header_length = 5,
    length_offset = 4,
    length = request_length,
    data_offset = 5,
    crc_offset = request_crc_offset,
    ack_offset = request_ack_offset,
  }

  local reply = nil
  local reply_offset = request_ack_offset + 1
  if reply_offset < raw_length and raw_tvb(request_ack_offset, 1):uint() == 0x00 then
    local reply_length = raw_tvb(reply_offset, 1):uint()
    local reply_crc_offset = reply_offset + 1 + reply_length
    local reply_ack_offset = reply_crc_offset + 1
    if reply_ack_offset >= raw_length then
      return nil, "reply segment truncated"
    end
    reply = {
      offset = reply_offset,
      length_offset = reply_offset,
      length = reply_length,
      data_offset = reply_offset + 1,
      crc_offset = reply_crc_offset,
      ack_offset = reply_ack_offset,
    }
  end

  return {
    request = request,
    reply = reply,
  }
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
  request = ProtoField.string("helianthus_ebus.request", "Request"),
  request_length = ProtoField.uint8("helianthus_ebus.request.length", "Request length", base.DEC),
  request_data = ProtoField.bytes("helianthus_ebus.request.data", "Request data"),
  request_crc = ProtoField.uint8("helianthus_ebus.request.crc", "Request CRC", base.HEX),
  request_ack = ProtoField.uint8("helianthus_ebus.request.ack", "Request ACK", base.HEX),
  reply = ProtoField.string("helianthus_ebus.reply", "Reply"),
  reply_length = ProtoField.uint8("helianthus_ebus.reply.length", "Reply length", base.DEC),
  reply_data = ProtoField.bytes("helianthus_ebus.reply.data", "Reply data"),
  reply_crc = ProtoField.uint8("helianthus_ebus.reply.crc", "Reply CRC", base.HEX),
  reply_ack = ProtoField.uint8("helianthus_ebus.reply.ack", "Reply ACK", base.HEX),
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
    pinfo.cols.src = ""
    pinfo.cols.dst = ""
    pinfo.cols.protocol = "HLTH-ENS"
    pinfo.cols.info = string.format("ENS %s data=0x%02X", plugin.command_name(command), raw_length > 0 and raw_tvb(0, 1):uint() or 0)
    return
  end

  if raw_length >= 1 then
    subtree:add(fields.qq, raw_tvb(0, 1))
  end
  if raw_length >= 2 then
    subtree:add(fields.zz, raw_tvb(1, 1))
  end
  local qq = raw_length >= 1 and raw_tvb(0, 1):uint() or 0
  local zz = raw_length >= 2 and raw_tvb(1, 1):uint() or 0
  subtree:add(fields.pb, buffer(9, 1))
  subtree:add(fields.sb, buffer(10, 1))
  local opcode = lshift(pb, 8) + sb
  subtree:add(fields.opcode, buffer(9, 2))
  subtree:add(fields.opcode_label, plugin.lookup_label(opcode))
  subtree:add(fields.family, plugin.family_guess(opcode))
  local transaction_type = plugin.transaction_type(zz)
  subtree:add(fields.frame_type, transaction_type)

  if transaction_type == "Primary-Secondary" then
    local segments, segment_err = plugin.parse_primary_secondary_segments(raw_tvb)
    if segments == nil then
      subtree:add_expert_info(PI_MALFORMED, PI_WARN, segment_err)
    else
      local request = segments.request
      local request_tree = subtree:add(
        fields.request,
        raw_tvb(request.offset, request.ack_offset - request.offset + 1),
        string.format("Request (len=%d)", request.length)
      )
      request_tree:add(fields.request_length, raw_tvb(request.length_offset, 1))
      request_tree:add(fields.request_data, raw_tvb(request.data_offset, request.length))
      request_tree:add(fields.request_crc, raw_tvb(request.crc_offset, 1))
      request_tree:add(fields.request_ack, raw_tvb(request.ack_offset, 1))

      if segments.reply ~= nil then
        local reply = segments.reply
        local reply_tree = subtree:add(
          fields.reply,
          raw_tvb(reply.offset, reply.ack_offset - reply.offset + 1),
          string.format("Reply (len=%d)", reply.length)
        )
        reply_tree:add(fields.reply_length, raw_tvb(reply.length_offset, 1))
        reply_tree:add(fields.reply_data, raw_tvb(reply.data_offset, reply.length))
        reply_tree:add(fields.reply_crc, raw_tvb(reply.crc_offset, 1))
        reply_tree:add(fields.reply_ack, raw_tvb(reply.ack_offset, 1))
      else
        subtree:add(fields.reply, "Reply: <none>")
      end
    end
  end

  pinfo.cols.src = raw_length >= 1 and string.format("0x%02X", qq) or ""
  pinfo.cols.dst = raw_length >= 2 and string.format("0x%02X", zz) or ""
  pinfo.cols.protocol = string.format("%02X/%02X", pb, sb)
  local info = string.format(
    "%s opcode=0x%04X %s len=%d",
    transaction_type,
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
