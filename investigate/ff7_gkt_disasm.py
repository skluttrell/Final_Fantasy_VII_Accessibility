#!/usr/bin/env python3
"""
ff7_gkt_disasm.py -- One-off: dump GET_KERNEL_TEXT (0x41963C) itself to
find how the battle-section switch reaches the section-8 (battle
display text) handler — the v2.10 jump-table note was for the
section-7 path and the [8*4] read landed mid-code (2026-07-19).
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"gkt_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
_log = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s)
    _log.write(s)
    _log.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

def find_exe():
    for cand in (
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    ):
        if os.path.isfile(cand):
            return cand
    raise RuntimeError("exe not found")

with open(find_exe(), 'rb') as f:
    data = f.read()
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff = e_lfanew + 4
nsec = struct.unpack_from('<HH', data, coff)[1]
optsz = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
base = struct.unpack_from('<I', data, opt + 28)[0]
secoff = opt + optsz
secs = []
for i in range(nsec):
    o = secoff + i * 40
    vs, va, rs, rp = struct.unpack_from('<IIII', data, o + 8)
    secs.append((va, vs, rp))
def v2o(va):
    r = va - base
    for sva, svs, srp in secs:
        if sva <= r < sva + svs:
            return srp + (r - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

START = 0x41963C
print(f"GET_KERNEL_TEXT 0x{START:X}:")
jump_tables = []
for insn in md.disasm(data[v2o(START):v2o(START) + 0x300], START):
    if insn.id == 0:
        continue
    marks = []
    for op in insn.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.index != 0:
            d = op.mem.disp & 0xFFFFFFFF
            if 0x400000 <= d < 0xA00000:
                marks.append(f"TABLE 0x{d:X}")
                jump_tables.append(d)
        elif op.type == capstone.x86.X86_OP_MEM:
            d = op.mem.disp & 0xFFFFFFFF
            if 0x900000 <= d < 0xDE0000:
                marks.append(f"g_{d:X}")
    star = ("   ; " + ",".join(marks)) if marks else ""
    print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}")

print("\nJump tables seen:", ", ".join(f"0x{t:X}" for t in sorted(set(jump_tables))))
for t in sorted(set(jump_tables)):
    print(f"\ntable @0x{t:X} entries 0..15:")
    for i in range(16):
        v = struct.unpack_from('<I', data, v2o(t + i * 4))[0]
        print(f"  [{i:2}] 0x{v:08X}")
