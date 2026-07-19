#!/usr/bin/env python3
"""
ff7_battle_results_static.py -- Statically locate the battle VICTORY
screens' state (2026-07-19; user request + Screenshots/BattleScreen/
victory_screen_1..3.jpg ground truth).

KNOWN GOING IN (FFNx, all name/operand-anchored):
  - menu_battle_end_sub_6C9543 = THE results screen sub (FFNx replaces
    its call site for achievements).
  - menu_battle_end_mode = u16 at gav(0x6C9543+0x2C); FFNx's hook
    branches: 0 = battle won (init), 1 = EXP/level phase (level
    achievements fire), 3 = gil phase (gil achievement fires) — i.e.
    THE SCREEN-PHASE VARIABLE, resolved here.
  - Savemap consumers we already trust: char record exp u32 at +0x3C
    (records 0xDBFD8C stride 0x84), gil u32 at 0xDC08B4.

HUNTED HERE:
  1. The mode variable's address (print it).
  2. The GAINED pools (EXP, AP, gil) + item-drops list: mine the sub
     (BFS depth 3) for (a) references to the FF7-encoded captions
     "Gained EXP and AP."/"Gained gil."/"No items", (b) the code that
     ADDS into savemap gil / char exp — the source operands of those
     adds ARE the gained pools; context windows printed for eyeballing.
"""
import sys, os, struct, datetime
from collections import defaultdict
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_results_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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
def off_to_va(off):
    for sva, svs, srp in secs:
        if srp <= off < srp + svs:
            return base + sva + (off - srp)
    return None

SUB = 0x6C9543
mode_va = struct.unpack_from('<I', data, v2o(SUB + 0x2C))[0]
print(f"menu_battle_end_mode (operand at 0x6C9543+0x2C) = 0x{mode_va:X}\n")

def ff7_encode(s):
    return bytes((ord(c) - 0x20) & 0xFF for c in s)

STR_VAS = {}
for label in ("Gained EXP and AP.", "Gained gil.", "No items", "Level UP!!"):
    pat = ff7_encode(label)
    idx, hits = 0, []
    while True:
        idx = data.find(pat, idx)
        if idx < 0:
            break
        va = off_to_va(idx)
        if va is not None:
            hits.append(va)
            STR_VAS[va] = label
        idx += 1
    print(f'"{label}": ' + (", ".join(f"0x{v:X}" for v in hits) or "NOT FOUND"))
print()

SAVEMAP_GIL   = 0xDC08B4
CHAR_RECORDS  = 0xDBFD8C

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

KNOWN = {
    SAVEMAP_GIL: "SAVEMAP_GIL", mode_va: "BATTLE_END_MODE",
    0xDC08BC: "countdown_secs", 0xDC12DC: "MENU_OPEN",
    CHAR_RECORDS: "CHAR_RECORDS",
}

# BFS the results sub; record instructions of interest.
seen, frontier = set(), [SUB]
interesting = []      # (insn_va, why)
for depth in range(3):
    nxt = []
    for fva in frontier:
        if fva in seen or len(seen) > 250:
            continue
        seen.add(fva)
        foff = v2o(fva)
        if foff is None:
            continue
        for insn in md.disasm(data[foff:foff + 0x2000], fva):
            if insn.id == 0:
                continue
            if insn.mnemonic == 'call':
                try:
                    tgt = int(insn.op_str, 16)
                    if 0x6C0000 <= tgt < 0x720000:
                        nxt.append(tgt)
                except ValueError:
                    pass
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM and \
                        (op.imm & 0xFFFFFFFF) in STR_VAS:
                    interesting.append(
                        (insn.address, "CAPTION " + STR_VAS[op.imm & 0xFFFFFFFF]))
                if op.type == capstone.x86.X86_OP_MEM:
                    d = op.mem.disp & 0xFFFFFFFF
                    if d == SAVEMAP_GIL:
                        interesting.append((insn.address, "SAVEMAP_GIL access"))
                    elif d == mode_va:
                        interesting.append((insn.address, "MODE access"))
                    elif CHAR_RECORDS + 0x3C <= d < CHAR_RECORDS + 0x84 and \
                            op.mem.base != 0:
                        interesting.append(
                            (insn.address, f"char-record +0x{d-CHAR_RECORDS:X} indexed"))
    frontier = nxt

print(f"swept {len(seen)} functions; {len(interesting)} interesting sites\n")

printed = set()
for iva, why in sorted(set(interesting)):
    wstart = iva - 0x50
    key = wstart & ~0x1F
    print(f"--- {why} @0x{iva:X} ---")
    if key in printed:
        print("    (window overlaps one above)\n")
        continue
    printed.add(key)
    woff = v2o(wstart)
    if woff is None:
        continue
    for insn in md.disasm(data[woff:woff + 0xB0], wstart):
        if insn.id == 0:
            continue
        marks = []
        for op in insn.operands:
            d = None
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
            elif op.type == capstone.x86.X86_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if v in STR_VAS:
                    marks.append("str:" + STR_VAS[v])
                if 0x990000 <= v < 0xDE0000:
                    d = v
            if d is not None and 0x990000 <= d < 0xDE0000:
                marks.append(KNOWN.get(d, f"g_{d:X}"))
        star = ("   ; " + ",".join(marks)) if marks else ""
        cur = " <<<<" if insn.address == iva else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}{cur}")
    print()
