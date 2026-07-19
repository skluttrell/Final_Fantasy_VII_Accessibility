#!/usr/bin/env python3
"""
ff7_results_block_refs.py -- One-off: find every code reference to the
battle-results block neighborhood 0x99E2B0..0x99E340 (gained-gil proven
at 0x99E2C8, drops array at 0x99E2F0/F4 — ff7_battle_results_static.py
2026-07-19) by scanning the exe for the little-endian address bytes and
disassembling a context window around each hit. Goal: pin the gained
EXP and AP pools (expected near 0x99E2C0/0x99E2C4) and the drops array
layout.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"results_block_refs_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.skipdata = True

TEXT_LO, TEXT_HI = 0x401000, 0x800000
hits_by_target = {}
for target in range(0x99E2B0, 0x99E344, 4):
    pat = struct.pack('<I', target)
    idx, sites = 0, []
    while True:
        idx = data.find(pat, idx)
        if idx < 0:
            break
        va = off_to_va(idx)
        idx += 1
        if va is None or not (TEXT_LO <= va < TEXT_HI):
            continue
        sites.append(va)
    if sites:
        hits_by_target[target] = sites
        print(f"0x{target:X}: {len(sites)} code-embedded refs: " +
              " ".join(f"0x{v:X}" for v in sites[:8]))

print("\nContext (one window per target, first ref):")
for target, sites in hits_by_target.items():
    va = sites[0]
    wstart = va - 0x30
    woff = v2o(wstart)
    print(f"\n--- 0x{target:X} first ref near 0x{va:X} ---")
    for insn in md.disasm(data[woff:woff + 0x60], wstart):
        if insn.id == 0:
            continue
        mark = "   <==" if insn.address <= va < insn.address + insn.size else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{mark}")
