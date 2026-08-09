#!/usr/bin/env python3
"""
ff7_battle_miss_static4.py -- fourth pass: find the WRITER of the
damage-event records (stride 0xE; known read fields relative to
0x9ABA0A: +0 display value, +2 flags, +8, +0xA) and the writer of the
anim-event queue entries (stride 0xC at 0x9ACB98: +0 attacker, +3
damage-record idx). Passes 1-3 found only READERS via those exact
constants -- the writers must address the arrays via neighboring base
constants (other field offsets fold into the displacement) or via the
allocation/count variables.

Sweep the whole plausible constant neighborhood of both arrays plus
the runner's index globals; dump windows around every hit that is NOT
in the already-mapped reader region (0x42CF00-0x42E200). The writer's
branch structure around a `mov word [...], 0xFFFF/FFFE/FFFD` tells us
what -1/-2/-3 (MISS glyph vs the two mystery glyph displays) mean in
game terms.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_miss_static4_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

exe_path = find_exe()
print(f"exe: {exe_path}")
with open(exe_path, 'rb') as f:
    data = f.read()
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff = e_lfanew + 4
nsec = struct.unpack_from('<HH', data, coff)[1]
optsz = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
base = struct.unpack_from('<I', data, opt + 28)[0]
secoff = opt + optsz
secs = []
text_lo = text_hi = text_rp = None
for i in range(nsec):
    o = secoff + i * 40
    name = data[o:o + 8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', data, o + 8)
    secs.append((va, vs, rp))
    if name == '.text':
        text_lo, text_hi, text_rp = base + va, base + va + vs, rp

def v2o(va):
    r = va - base
    for sva, svs, srp in secs:
        if sva <= r < sva + svs:
            return srp + (r - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def scan_text_for_u32(value):
    pat = struct.pack('<I', value)
    hits = []
    start = text_rp
    end = text_rp + (text_hi - text_lo)
    i = data.find(pat, start, end)
    while i != -1:
        hits.append(text_lo + (i - text_rp))
        i = data.find(pat, i + 1, end)
    return hits

def dump_window(label, hit_va, before=0x50, after=0x60):
    start = hit_va - before
    off = v2o(start)
    if off is None:
        return
    print(f"-- {label}: window around 0x{hit_va:X} --")
    for insn in md.disasm(data[off:off + before + after], start):
        if insn.id == 0:
            continue
        tag = "  <== HIT" if insn.address <= hit_va < insn.address + insn.size else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{tag}")
    print()

# Neighborhood: damage-record array (base near 0x9ABA0A, stride 0xE,
# 78+ records = spans ~0x450 bytes; a writer of record field +N uses
# constant base+N) and anim-event array (base 0x9ACB98, stride 0xC).
# Sweep every even offset base-0x10..base+0x10 for both, plus the
# runner/allocation globals.
READER_LO, READER_HI = 0x42C000, 0x42E300
cands = []
for delta in range(-0x10, 0x12, 2):
    cands.append(0x9ABA0A + delta)
for delta in range(-8, 0xE):
    cands.append(0x9ACB98 + delta)
cands += [0xBF2A38, 0xBFD094]
seen_any = False
for c in cands:
    hits = scan_text_for_u32(c)
    outside = [h for h in hits if not (READER_LO <= h <= READER_HI)]
    if not hits:
        continue
    print(f"### 0x{c:X}: {len(hits)} hits total, "
          f"{len(outside)} outside the mapped reader region")
    if len(outside) > 40:
        print("    (over 40 outside -- addresses only)")
        print("    " + ", ".join(f"0x{h:X}" for h in outside))
        print()
        continue
    for h in outside:
        seen_any = True
        dump_window(f"g_0x{c:X}", h)
if not seen_any:
    print("NO writer sites outside the reader region for any candidate "
          "constant -- the writers must use register-relative addressing "
          "(pointer into the array).")
print("DONE.")
