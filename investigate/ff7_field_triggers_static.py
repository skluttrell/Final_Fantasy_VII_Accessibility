#!/usr/bin/env python3
"""
ff7_field_triggers_static.py -- Statically resolve the field TRIGGERS HEADER
pointer (parsed field-file section 8: gateways/exits, triggers, arrows, the
field's own name, and control_direction) from ff7_en.exe on disk (2026-07-13).

WHY:
  First step of the field navigation system: an on-demand "exit scan" that
  announces each active gateway's direction and walking distance. The parsed
  section-8 data lives behind ONE global pointer that FFNx names
  field_triggers_header:

      ff7_data.h:337  field_sub_6388EE            = grc(field_main_loop, 0xFF)
      ff7_data.h:338  field_draw_everything       = grc(field_sub_6388EE, 0x11)
      ff7_data.h:341  field_pick_tiles_make_vertices = grc(field_draw_everything, 0xC9)
      ff7_data.h:350  field_layer3_pick_tiles     = grc(field_pick_tiles_make_vertices, 0x12)
      ff7_data.h:368  field_triggers_header       = gav(field_layer3_pick_tiles, 0x134)

  field_main_loop needs a live game object (the session-3 dead end), but
  field_sub_6388EE's NAME embeds its US-1.02 address (0x6388EE) -- the same
  anchor trick that cracked the battle menu (ff7_battle_menu_static.py).
  The chain then SELF-VALIDATES three independent ways, because three other
  FFNx externals resolved from the same function also embed their addresses:

      gav(field_layer3_pick_tiles, 0x009) must == 0xCFFE3C  (do_draw_layer3_CFFE3C)
      gav(field_layer3_pick_tiles, 0x07A) must == 0xCFF3D8  (field_camera_rotation_matrix_CFF3D8)
      grc(field_layer3_pick_tiles, 0x07E) must == 0x623C0F  (field_layer_sub_623C0F)

  If all three land, field_triggers_header read off the same instruction
  stream is trusted exactly as much as FFNx itself.

STRUCT (FFNx ff7.h field_trigger_header, offsets computed from the packed
layout -- printed below for the implementation):
      +0x00 byte field_name[9]      (ASCII field name)
      +0x09 byte control_direction  (input rotation for this field, 0-255 = 0-360deg)
      +0x38 field_gateway gateways[12]   (24 bytes each:
              3x vector3<short> exit line v1/v2 + destination, short field_id,
              4 unknown bytes; 0x7FFF field_id / degenerate line = unused)
      +0x158 field_trigger triggers[12]  (16 bytes each, bg toggles)

Output: the resolved pointer-holding global + all cross-check results.
"""
import sys, os, struct, datetime, subprocess

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"field_triggers_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

def find_exe_path():
    try:
        out = subprocess.check_output(
            ['wmic', 'process', 'where', "name='ff7_en.exe'", 'get', 'ExecutablePath'],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.lower().endswith('.exe'):
                return line
    except Exception:
        pass
    for cand in (
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    ):
        if os.path.isfile(cand):
            return cand
    raise RuntimeError("Could not locate ff7_en.exe")

exe_path = find_exe_path()
print(f"Reading exe: {exe_path}")
with open(exe_path, 'rb') as f:
    data = f.read()
print(f"  {len(data):,} bytes\n")

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\0\0'
coff_off = e_lfanew + 4
num_sections = struct.unpack_from('<HH', data, coff_off)[1]
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + opt_hdr_size
sections = []
for i in range(num_sections):
    off = section_off + i * 40
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    sections.append((va, vs, rp))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

def grc(addr, offset):
    """FFNx get_relative_call: E8 rel32 at addr+offset -> call target."""
    off = va_to_off(addr + offset)
    opcode = data[off]
    if opcode != 0xE8:
        return None, f"opcode at 0x{addr+offset:08X} is 0x{opcode:02X}, not E8 CALL"
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return addr + offset + 5 + rel, None

def gav(addr, offset):
    """FFNx get_absolute_value: u32 immediate at addr+offset."""
    return struct.unpack_from('<I', data, va_to_off(addr + offset))[0]

print("Chain resolution (anchor: field_sub_6388EE = 0x6388EE, from the FFNx name):")
ANCHOR = 0x6388EE

fde, err = grc(ANCHOR, 0x11)
print(f"  field_draw_everything          = grc(0x{ANCHOR:X}, 0x11)  = "
      f"{'0x%08X' % fde if fde else 'FAIL: ' + err}")
fptmv, err = grc(fde, 0xC9)
print(f"  field_pick_tiles_make_vertices = grc(^, 0xC9)        = "
      f"{'0x%08X' % fptmv if fptmv else 'FAIL: ' + err}")
fl3pt, err = grc(fptmv, 0x12)
print(f"  field_layer3_pick_tiles        = grc(^, 0x12)        = "
      f"{'0x%08X' % fl3pt if fl3pt else 'FAIL: ' + err}")
print()

print("Cross-checks (FFNx name-embedded addresses):")
c1 = gav(fl3pt, 0x009)
c2 = gav(fl3pt, 0x07A)
c3, err3 = grc(fl3pt, 0x07E)
ok1 = c1 == 0xCFFE3C
ok2 = c2 == 0xCFF3D8
ok3 = c3 == 0x623C0F
print(f"  gav(fl3pt, 0x009) = 0x{c1:08X}  expect 0xCFFE3C (do_draw_layer3)          {'OK' if ok1 else '** MISMATCH **'}")
print(f"  gav(fl3pt, 0x07A) = 0x{c2:08X}  expect 0xCFF3D8 (camera rotation matrix)  {'OK' if ok2 else '** MISMATCH **'}")
print(f"  grc(fl3pt, 0x07E) = {'0x%08X' % c3 if c3 else 'FAIL'}  expect 0x623C0F (field_layer_sub)          {'OK' if ok3 else '** MISMATCH **'}")
print()

if ok1 and ok2 and ok3:
    hdr_ptr = gav(fl3pt, 0x134)
    print(f"ALL CROSS-CHECKS PASSED.")
    print(f"FIELD_TRIGGERS_HEADER_PTR = gav(fl3pt, 0x134) = 0x{hdr_ptr:08X}")
    print(f"  (global holding field_trigger_header*; header layout in docstring:")
    print(f"   +0x00 field_name[9], +0x09 control_direction,")
    print(f"   +0x38 gateways[12] (24B each), +0x158 triggers[12])")
else:
    print("CHAIN INVALID -- do not trust the header pointer; re-derive offsets"
          " against the vendored FFNx source (offsets may have drifted).")

print(f"\nLog saved to: {_log_path}")
_log_file.close()
