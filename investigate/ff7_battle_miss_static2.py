#!/usr/bin/env python3
"""
ff7_battle_miss_static2.py -- follow-up to ff7_battle_miss_static.py
(same day). Session 1 decoded the DISPLAY side:

  anim-script opcode 0xC2 handler (inside run_animation_script,
  ~0x4223C4..): fills an effect100 slot (data base 0xBFB718, stride
  0x20, current-slot index word [0xBF23B8]):
    +0x08 <- target actor id  (movsx from byte [0xBFCDE0])
    +0x0A <- DISPLAY VALUE word from [0x42DE25(actor)*0xC + 0xBF2A40]
    (+0x06/+0x0E/+0x19 filled past the first dump's window -- cut off)
  battle_sub_425D29 (the effect100 fn) re-posts the data to two
  effect60 fns: display_battle_damage_5BB410 (slot+0x0E = value,
  +0x10 = actor, +0x14 = flags) and battle_sub_425E5F.
  5BB410's draw helper 0x5BB756 SWITCHES ON THE VALUE WORD:
    -1 -> glyph sprite at tex(0x80,0x88) 0x18x0xB   <- MISS candidate
    -2 -> glyph at tex(0x20,0xE0) 0x20x0xA
    -3 -> TWO stacked glyphs tex(0x20,0xEA)+(0x20,0xF4)
    else -> digit rendering (flags bit 2 adds a tag glyph -- MP?)

So the per-target result the mod needs is THE VALUE WORD in the
0xBF2A40 table (stride 0xC): 0xFFFF/-1 = miss-class display. This
session pins down:
  A. the full 0xC2 handler (all effect100 fields + any second value
     channel -- MP damage lives somewhere);
  B. 0x42DE25 (actor id -> display-table row mapping);
  C. 0x425F3F (the [0xBF2DF0] actor-mask gate) + the sibling trigger
     at 0x42602F (second push 0x5BB410 site -- which opcode?);
  D. THE WRITERS of the 0xBF2A40 table = the damage-calc side. The
     branch that stores -1 tells us the exact game meaning (to-hit
     roll failure vs immune vs death), same for -2/-3;
  E. the rest of 5BB756's digit path (beyond the first dump's budget)
     to map the flags word's bits.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_miss_static2_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

def dump_window(label, hit_va, before=0x30, after=0x40):
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

# A: the full 0xC2 handler region. Session 1 saw 0x4223C4..0x422461 (cut
# mid-instruction); the handler plausibly starts earlier (opcode compare)
# and continues filling +0x06/+0x0E/+0x19. 0x400 window covers it.
dump("anim-script 0xC2 handler region (run_animation_script body)",
     0x422300, 0x400, stop_at_ret=False)

# B: actor id -> display-table row. Small leaf expected.
dump("sub_42DE25 (actor -> 0xBF2A40 row index)", 0x42DE25, 0x100)

# C1: the mask gate called before every display enqueue.
dump("sub_425F3F (actor-mask gate on [0xBF2DF0])", 0x425F3F, 0x80)

# C2: the sibling effect100 fn containing the second push 0x5BB410
# (0x42604E). Starts somewhere after 425F3F's ret; 0x425F87 is a
# plausible entry -- dump generously from there.
dump("sibling display trigger (second enqueue site region)",
     0x425F87, 0x300, stop_at_ret=False)

# E: rest of the draw helper's digit path + the digit-split helper the
# first dump cut off (0x5BB910 was the budget end).
dump("5BB756 continuation (digit path + flags bits)", 0x5BB8CB, 0x180,
     stop_at_ret=False)
dump("sub_5BB9C9 (value -> digit array, sets [0xC05FF0] count)",
     0x5BB9C9, 0x100)

# D: THE WRITERS. Sweep .text for the display-value table base 0xBF2A40
# and the anim-script current-target byte 0xBFCDE0. Windows show operand
# role; writers outside the 0x422xxx/0x425Fxx/0x42Dxxx display code are
# the damage-calc side we are hunting.
for g in (0xBF2A40, 0xBFCDE0, 0xBF2DF0):
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
