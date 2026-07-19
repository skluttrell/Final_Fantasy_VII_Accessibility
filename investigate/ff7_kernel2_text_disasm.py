#!/usr/bin/env python3
"""
ff7_kernel2_text_disasm.py -- Follow-ups for the battle-dialog/list
fixes (2026-07-19):
 1. dump the per-section tables GET_KERNEL_TEXT uses (0x7B74A0 idx
    offsets, 0x7B74A8 kernel2 file bases) and disassemble
    kernel2_get_text (0x419457) — the mod will replicate its pointer
    chain to read battle text (section 8) without calling game code;
 2. dump BATTLE_MENU_FN_TABLE[5]/[6] (item/magic list state handlers)
    hunting the Confirm path's entry-index computation (the *6 access)
    to correct the v2.9 "w0+w4+scroll" formula for multi-column lists.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_text_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

def dump(label, start, length):
    print("=" * 70)
    print(f"{label}: 0x{start:X} (+0x{length:X})")
    print("=" * 70)
    off = v2o(start)
    if off is None:
        print("  (unmapped)")
        return
    for insn in md.disasm(data[off:off + length], start):
        if insn.id == 0:
            continue
        marks = []
        for op in insn.operands:
            d = None
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
            elif op.type == capstone.x86.X86_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if 0x900000 <= v < 0xDE0000:
                    d = v
            if d is not None and 0x900000 <= d < 0xDE0000:
                marks.append(f"g_{d:X}")
        star = ("   ; " + ",".join(marks)) if marks else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}")
    print()

print("per-section tables (index = get_kernel_text section 0..8):")
off_a0 = v2o(0x7B74A0)
off_a8 = v2o(0x7B74A8)
print("  0x7B74A0 idx-offsets :", " ".join(f"{data[off_a0+i]:02x}" for i in range(9)))
print("  0x7B74A8 file bases  :", " ".join(f"{data[off_a8+i]:02x}" for i in range(9)))
print()

dump("kernel2_get_text (0x419457)", 0x419457, 0x1E0)

for st in (5, 6):
    h = struct.unpack_from('<I', data, v2o(0x91E6B8 + st * 4))[0]
    dump(f"BATTLE_MENU_FN_TABLE[{st}] = state-{st} handler", h, 0x500)
