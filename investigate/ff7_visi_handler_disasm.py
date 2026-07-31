#!/usr/bin/env python3
"""
ff7_visi_handler_disasm.py -- find the byte the VISI opcode (0xA4) writes
(2026-07-31, task-2: picked-up items must leave the pathfinder).

CONTEXT: ff7_prop_interact_catalog.py proved the hide mechanism offline —
the reactor potion (nmkin_3 'po0') and materia (nmkin_5 'mtr') pickup
talk scripts all reach VISI. The engine must store the per-model
visibility somewhere the renderer checks each frame; whatever the VISI
HANDLER writes is that somewhere, and the mod can read it to drop
collected pickups from the Items category live.

METHOD (static, playbook rule 1 — file VAs are runtime VAs, no ASLR):
  1. Find execute_opcode_table in the exe the same way the mod's own
     Resolve() does: known handler anchors. IDLCK's handler is DOCUMENTED
     in ff7_addresses.h: execute_opcode_table[0x6D] = 0x61E29F. Scan the
     exe image for a dword sequence where [0x6D] == 0x61E29F — that hit
     IS the table (cross-check: [0x40]/[0x48] must be plausible .text
     addresses, and [0x00]..[0xFF] all in module range).
  2. handler = table[0xA4]; capstone-disassemble it (restart past
     undecodable bytes — the v2.30.26 lesson).
  3. Report every MEMORY WRITE with its addressing form. The expected
     shape: fetch current entity's bound model index, index a per-model
     structure, store the operand byte. If the write lands at
     [reg*0x88 + base + disp] or [reg + disp] after a *0x88 multiply,
     disp is a field_event_data offset. If it lands in a DIFFERENT
     array, the base address tells us which.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"visi_handler_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore_stdout():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore_stdout)
print(f"Output saving to: {_log_path}\n")

import capstone

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
]
exe_path = next((c for c in EXE_CANDIDATES if os.path.isfile(c)), None)
if not exe_path:
    print("ERROR: ff7_en.exe not found")
    sys.exit(1)
print(f"Reading: {exe_path}")
img = open(exe_path, 'rb').read()

# -- PE mapping: file offset <-> VA ------------------------------------------------
pe = struct.unpack_from('<I', img, 0x3C)[0]
n_sec = struct.unpack_from('<H', img, pe + 6)[0]
opt_sz = struct.unpack_from('<H', img, pe + 20)[0]
image_base = struct.unpack_from('<I', img, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + opt_sz + i * 40
    vsz, va, rsz, ro = struct.unpack_from('<4I', img, s + 8)
    secs.append((va, vsz, ro, rsz))
print(f"image base 0x{image_base:X}, {n_sec} sections")

def va_to_off(va):
    rva = va - image_base
    for sva, vsz, ro, rsz in secs:
        if sva <= rva < sva + max(vsz, rsz):
            return ro + (rva - sva)
    return None

def off_to_va(off):
    for sva, vsz, ro, rsz in secs:
        if ro <= off < ro + rsz:
            return image_base + sva + (off - ro)
    return None

# -- 1. locate execute_opcode_table -------------------------------------------------
IDLCK_HANDLER = 0x0061E29F      # ff7_addresses.h provenance note
needle = struct.pack('<I', IDLCK_HANDLER)
table_va = None
pos = -1
while True:
    pos = img.find(needle, pos + 1)
    if pos < 0:
        break
    # candidate table start = this hit minus 0x6D dwords
    t_off = pos - 0x6D * 4
    if t_off < 0:
        continue
    ok = True
    for k in range(256):
        v = struct.unpack_from('<I', img, t_off + k * 4)[0]
        if not (image_base <= v < image_base + 0x00A00000):
            ok = False
            break
    if ok:
        table_va = off_to_va(t_off)
        print(f"execute_opcode_table @ VA 0x{table_va:08X} (file 0x{t_off:X})")
        break
if table_va is None:
    print("ERROR: opcode table not found")
    sys.exit(1)

t_off = va_to_off(table_va)
h_mes  = struct.unpack_from('<I', img, t_off + 0x40 * 4)[0]
h_ask  = struct.unpack_from('<I', img, t_off + 0x48 * 4)[0]
h_visi = struct.unpack_from('<I', img, t_off + 0xA4 * 4)[0]
print(f"  [0x40] MESSAGE = 0x{h_mes:08X}")
print(f"  [0x48] ASK     = 0x{h_ask:08X}")
print(f"  [0xA4] VISI    = 0x{h_visi:08X}")

# -- 2/3. disassemble the VISI handler, print memory writes -------------------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

h_off = va_to_off(h_visi)
codebytes = img[h_off:h_off + 0x200]
print(f"\n=== VISI handler @ 0x{h_visi:08X} ===")
addr = h_visi
end = h_visi + 0x200
writes = []
while addr < end:
    chunk_off = va_to_off(addr)
    done = False
    for ins in md.disasm(img[chunk_off:chunk_off + (end - addr)], addr):
        print(f"  0x{ins.address:08X}: {ins.mnemonic:8s} {ins.op_str}")
        # memory-destination writes
        if ins.mnemonic.startswith('mov') and ',' in ins.op_str:
            dst = ins.op_str.split(',')[0]
            if '[' in dst:
                writes.append((ins.address, ins.mnemonic, ins.op_str))
        if ins.mnemonic == 'ret':
            done = True
            break
        addr = ins.address + ins.size
    else:
        # undecodable byte: restart past it (v2.30.26 capstone lesson)
        if not done and addr < end:
            print(f"  0x{addr:08X}: ?? {img[va_to_off(addr)]:02X} (skip)")
            addr += 1
            continue
    break

print("\n=== MEMORY WRITES in handler ===")
for a, m, o in writes:
    print(f"  0x{a:08X}: {m} {o}")
print("\nInterpretation notes:")
print("  field_event_data stride = 0x88; its array base pointer lives at")
print("  0x00CC0B60 (FIELD_EVENT_DATA_PTR). A write of the form")
print("  [reg + reg*8 + ...] or with 0x88-scaled math into that array is a")
print("  field_event_data field; a write to a different static array is a")
print("  separate per-model table (report its base).")
