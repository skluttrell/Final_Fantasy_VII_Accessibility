#!/usr/bin/env python3
"""
ff7_battle_miss_static3.py -- third pass of the miss-display hunt
(2026-08-09). Sessions 1-2 established:

  DISPLAY: effect60 fn display_battle_damage_5BB410; its data slot
  (base 0xBFC3A0, stride 0x20, same index as the fn array) carries
  +0x0E value word (-1/-2/-3 = glyph displays, else digits),
  +0x10 target actor id, +0x14 flags word. THREE trigger paths (anim
  opcode 0xC2 at 0x4223F3, sibling 0x42604E, direct copier 0x42E156)
  all enqueue 0x5BB410 -- so WATCHING THE EFFECT60 FN ARRAY for
  0x5BB410 entries catches every damage display, including the MP
  channel and multi-hit paths.

  DATA FLOW: staging table 0xBF2A40 (stride 0xC, actor ids parallel
  at 0xC05E68[0x4E]) is COPIED (0x42D4CA) from the engine's original
  event records: value word [0x9ABA0A + idx*0xE], flags word
  [0x9ABA0C + idx*0xE] -- a 14-byte-stride record array in battle
  module data, reached via byte [0x9ACB9B + n*0xC] out of word
  [0x9AAD7A + m*0xC].

THIS PASS:
  A. add_fn_to_effect60_fn (0x5BED92) + add_fn_to_effect100_fn
     (0x5BEC50): the fn ARRAY base + slot count (the mod will poll
     fn_array[i] == 0x5BB410 and read data slot i).
  B. execute_effect60_fn: find who iterates the fn array (confirms
     count + the current-index global 0xBF2DF4 write).
  C. THE SEMANTICS: sweep refs to the original record fields
     0x9ABA0A/0x9ABA0C and the intermediate tables 0x9ACB9B/0x9AAD7A.
     The WRITERS (expected in the 0x5C**** damage-calc region) show
     the conditions that store the sentinels: which of -1/-2/-3 is
     the to-hit-roll MISS, and what the other two mean (death?
     immune?). Without this, speaking "miss" for -2/-3 could be
     WRONG -- the glyph coordinates alone don't name themselves.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_miss_static3_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

def dump(label, start, length, stop_at_ret=True):
    print("=" * 70)
    print(f"{label}: 0x{start:X} (+0x{length:X})")
    print("=" * 70)
    off = v2o(start)
    if off is None:
        print("  <unmapped VA>")
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
                if 0x400000 <= v < 0xDE0000:
                    d = v
            if d is not None and 0x900000 <= d < 0xDE0000:
                marks.append(f"g_{d:X}")
        star = ("   ; " + ",".join(marks)) if marks else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}")
        if stop_at_ret and insn.mnemonic == 'ret':
            break
    print()

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

def dump_window(label, hit_va, before=0x40, after=0x50):
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

# A: the two effect-add functions -- fn array bases + capacity loops.
dump("add_fn_to_effect100_fn (0x5BEC50)", 0x5BEC50, 0x120)
dump("add_fn_to_effect60_fn (0x5BED92)", 0x5BED92, 0x120)

# B: who executes effect60 entries (writes current idx [0xBF2DF4]).
hits = scan_text_for_u32(0xBF2DF4)
print(f"### [0xBF2DF4] (current effect60 idx): {len(hits)} hits")
outside = [h for h in hits
           if not (0x425D00 <= h <= 0x426200 or 0x5BB400 <= h <= 0x5BBA00)]
for hit in outside[:12]:
    dump_window("effect60 idx ref", hit)

# C: the original event records + index tables. Writers reveal the
# sentinel meanings. Cap generously; these are battle-module tables.
for g in (0x9ABA0A, 0x9ABA0C, 0x9ACB9B, 0x9AAD7A, 0xBFD088):
    hits = scan_text_for_u32(g)
    print(f"### global 0x{g:X}: {len(hits)} .text hits")
    if len(hits) > 80:
        print("    (over 80 -- addresses only)")
        print("    " + ", ".join(f"0x{h:X}" for h in hits))
        print()
        continue
    for hit in hits:
        dump_window(f"g_0x{g:X}", hit)
print("DONE.")
