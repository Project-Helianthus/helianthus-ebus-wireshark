local plugin = dofile("dissectors/helianthus-ebus.lua")

local function count_entries(tbl)
  local count = 0
  for _ in pairs(tbl) do
    count = count + 1
  end
  return count
end

assert(count_entries(plugin.semantic_ebus_opcodes) == 46, "expected 46 eBUS semantic opcodes")
assert(count_entries(plugin.semantic_vaillant_opcodes) == 18, "expected 18 Vaillant semantic opcodes")
assert(plugin.lookup_label(0xB524) == "Vaillant B524 extended registers", "missing B524 label")
assert(plugin.lookup_label(0xB503) == "Vaillant B503", "missing B503 label")
assert(plugin.lookup_label(0xB513) == "Vaillant B513", "missing B513 label")
assert(plugin.lookup_label(0xB514) == "Vaillant B514", "missing B514 label")
assert(plugin.lookup_label(0xB515) == "Vaillant B515", "missing B515 label")
assert(plugin.lookup_label(0xB521) == "Vaillant B521", "missing B521 label")
assert(plugin.lookup_label(0xB522) == "Vaillant B522", "missing B522 label")
assert(plugin.lookup_label(0xB523) == "Vaillant B523", "missing B523 label")
assert(plugin.lookup_label(0x1234) == "Raw opcode 0x1234", "unexpected fallback label")
assert(plugin.is_supported(0xB555), "expected B555 support")
assert(plugin.is_supported(0xB503), "expected B503 support")
assert(not plugin.is_supported(0xB599), "unexpected unsupported opcode support")

print("PASS: opcode catalog bootstrap")

