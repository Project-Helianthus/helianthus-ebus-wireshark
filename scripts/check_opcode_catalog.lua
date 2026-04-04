local plugin = dofile("dissectors/helianthus-ebus.lua")

local function count_entries(tbl)
  local count = 0
  for _ in pairs(tbl) do
    count = count + 1
  end
  return count
end

assert(count_entries(plugin.semantic_ebus_opcodes) == 46, "expected 46 eBUS semantic opcodes")
assert(count_entries(plugin.semantic_vaillant_opcodes) == 11, "expected 11 Vaillant semantic opcodes")
assert(plugin.lookup_label(0xB524) == "Vaillant B524 extended registers", "missing B524 label")
assert(plugin.lookup_label(0x1234) == "Raw opcode 0x1234", "unexpected fallback label")
assert(plugin.is_supported(0xB555), "expected B555 support")
assert(not plugin.is_supported(0xB599), "unexpected unsupported opcode support")

print("PASS: opcode catalog bootstrap")

