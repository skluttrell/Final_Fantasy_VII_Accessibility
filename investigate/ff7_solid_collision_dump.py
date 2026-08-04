#!/usr/bin/env python3
"""
ff7_solid_collision_dump.py -- dump the engine's model-vs-model collision
regions to find how a model is SKIPPED as an obstacle (2026-08-04, third
pass of the SOLID investigation).

The +0x72 sweep (ff7_solid_consumer_static.py) found four sites reading
TWO models' collision radii in adjacent instructions -- the pair test of
a collision routine: 0x637B91, 0x637DE6, 0x637F89, 0x63825D, plus a
strided read at 0x61650B and base-reg reads at 0x636704/0x636713. The
per-model skip test (the SOLID +0x5F gate, and whatever else the engine
checks -- e.g. +0x5E, +0x62 visible) must sit at the loop heads above
those reads. Dump generous spans with all candidate offsets marked.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"solid_collision_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
from capstone import x86

exe = next(c for c in (
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
) if os.path.isfile(c))
print(f"Reading: {exe}")
data = open(exe, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((va, vs, ro, rs))

def v2o(va):
    r = va - image_base
    for sva, svs, sro, srs in secs:
        if sva <= r < sva + max(svs, srs):
            return sro + (r - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

MARKS = {0x5E: "+0x5E ?", 0x5F: "+0x5F SOLID-OFF", 0x60: "+0x60 ?",
         0x61: "+0x61 talk-off", 0x62: "+0x62 visible",
         0x63: "+0x63 move-type", 0x72: "+0x72 radius",
         0x74: "+0x74 talk-r", 0x78: "+0x78 triangle",
         0x0C: "+0x0C pos"}

def dump(title, va, end_va):
    print(f"===== {title}: 0x{va:08X} .. 0x{end_va:08X} =====")
    addr = va
    while addr < end_va:
        o = v2o(addr)
        progressed = False
        for ins in md.disasm(data[o:o + (end_va - addr)], addr):
            progressed = True
            note = ""
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.disp in MARKS and \
                        (op.mem.base != 0 or op.mem.index != 0):
                    note = f"   ; <<< {MARKS[op.mem.disp]}"
            if ins.mnemonic == 'imul' and '0x88' in ins.op_str:
                note += "   ; stride 0x88"
            print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{note}")
            addr = ins.address + ins.size
        if not progressed:
            print(f"  0x{addr:X}: db 0x{data[o]:02X}")
            addr += 1
    print()

# The strided radius read inside an opcode-ish routine
dump("0x61650B region", 0x616440, 0x616580)
# The base-reg pair around 0x636704 (probably a helper: contact distance)
dump("0x636700 region", 0x636640, 0x636790)
# The big block with four pair-tests -- likely THE movement collision loop
dump("collision loop block", 0x637A80, 0x638330)

print("Done.")
