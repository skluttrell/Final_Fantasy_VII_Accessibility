#!/usr/bin/env python3
"""
ff7_solid_builder_dump.py -- find who builds the 32-entry collision
candidate list the pair-test routine 0x637ABB consumes, and where the
SOLID flag (+0x5F) gates entry into it (2026-08-04, pass 4).

The pair-test routine iterates [arg2] as 0x20 entries x 0x18 bytes with
byte +0xC == 1 meaning "test this one". The builder that sets +0xC is
the routine that must read field_event_data +0x5F (SOLID-off) -- yet the
exact-disp sweep found NO +0x5F reader in the field range, so the
builder either reads it as part of a wider access or through a copied
local. Steps:
  1. find all callers of 0x637ABB (E8 rel32 scan);
  2. dump each caller's function region;
  3. also sweep for `imul reg, reg, 0x18` and byte writes to [..+0xC]
     patterns near field_event_data addressing (imul 0x88 / 0xCC0B60)
     to catch the builder directly.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"solid_builder_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

MARKS = {0x5E: "+0x5E", 0x5F: "+0x5F SOLID-OFF", 0x62: "+0x62 visible",
         0x72: "+0x72 radius", 0x78: "+0x78 triangle", 0x0C: "+0x0C"}

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
            if ins.mnemonic == 'imul' and ('0x88' in ins.op_str or
                                           '0x18' in ins.op_str):
                note += "   ; stride"
            if '0xcc0b60' in ins.op_str:
                note += "   ; field_event_data base"
            print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{note}")
            addr = ins.address + ins.size
        if not progressed:
            print(f"  0x{addr:X}: db 0x{data[o]:02X}")
            addr += 1
    print()

# ---- callers of 0x637ABB ----------------------------------------------------
TARGET = 0x637ABB
callers = []
o = text_ro
end_o = text_ro + text_rs
while o < end_o - 5:
    if data[o] == 0xE8:
        rel = struct.unpack_from('<i', data, o + 1)[0]
        va = o2v(o)
        if va is not None and va + 5 + rel == TARGET:
            callers.append(va)
    o += 1
print("callers of 0x637ABB:", [hex(c) for c in callers], "\n")
for c in callers:
    dump(f"caller region around 0x{c:X}", c - 0x480, c + 0x120)

print("Done.")
