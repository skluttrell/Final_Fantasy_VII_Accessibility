#!/usr/bin/env python3
"""
ff7_solid_list_builder.py -- find every .text reference to the static
collision-candidate list 0xCC1F70 (0x20 entries x 0x18 bytes) and dump
the BUILDER that fills it -- the routine that must consume the SOLID
flag (+0x5F) when deciding which models are obstacles (2026-08-04,
pass 5 of the SOLID investigation).
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"solid_list_builder_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
text_va, text_vs, text_ro, text_rs = secs[0]

def v2o(va):
    r = va - image_base
    for sva, svs, sro, srs in secs:
        if sva <= r < sva + max(svs, srs):
            return sro + (r - sva)
    return None
def o2v(off):
    for sva, svs, sro, srs in secs:
        if sro <= off < sro + srs:
            return image_base + sva + (off - sro)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# Any dword immediate/displacement inside the list span 0xCC1F70..0xCC2270
# (0x20 * 0x18 = 0x300 bytes) counts as a reference.
LO, HI = 0xCC1F70, 0xCC1F70 + 0x300
refs = []
o = text_ro
end_o = text_ro + text_rs
while o < end_o - 4:
    v = struct.unpack_from('<I', data, o)[0]
    if LO <= v < HI:
        refs.append((o2v(o), v))
    o += 1
print(f"raw dword refs into 0xCC1F70..0x{HI:X}:")
for va, v in refs:
    print(f"  at 0x{va:X}: 0x{v:08X} (entry {(v - LO) // 0x18}, +0x{(v - LO) % 0x18:X})")

# Group into clusters and dump each cluster's surrounding code once.
clusters = []
for va, v in refs:
    if clusters and va - clusters[-1][1] < 0x400:
        clusters[-1] = (clusters[-1][0], va)
    else:
        clusters.append((va, va))

MARKS = {0x5E: "+0x5E", 0x5F: "+0x5F SOLID-OFF", 0x62: "+0x62 visible",
         0x72: "+0x72 radius", 0x78: "+0x78 triangle"}

def dump(title, va, end_va):
    print(f"\n===== {title}: 0x{va:08X} .. 0x{end_va:08X} =====")
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
                if op.type == x86.X86_OP_MEM and LO <= op.mem.disp < HI:
                    note += (f"   ; LIST entry+0x{(op.mem.disp - LO) % 0x18:X}")
                if op.type == x86.X86_OP_IMM and LO <= (op.imm & 0xFFFFFFFF) < HI:
                    note += "   ; LIST base imm"
            if ins.mnemonic == 'imul' and ('0x88' in ins.op_str or
                                           '0x18' in ins.op_str):
                note += "   ; stride"
            print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{note}")
            addr = ins.address + ins.size
        if not progressed:
            print(f"  0x{addr:X}: db 0x{data[o]:02X}")
            addr += 1

for lo, hi in clusters:
    dump(f"cluster", lo - 0x180, hi + 0x180)

print("\nDone.")
