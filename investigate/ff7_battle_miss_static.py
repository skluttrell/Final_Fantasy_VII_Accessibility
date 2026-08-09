#!/usr/bin/env python3
"""
ff7_battle_miss_static.py -- THE DAMAGE-DISPLAY WRITER HUNT (2026-08-09,
user request: "say 'miss' when any attack misses, enemy or party").

WHY: the v2.30.84/.89 battle damage watcher POLLS actor HP -- a miss
produces no HP change, so it is invisible (documented residual in
PARKED [BATTLELINE] since v2.30.84: "crits/misses still invisible to
HP polling -- needs the damage-display writer"). The sighted player
sees a floating "MISS" sprite over the target; we need the engine
mechanism that produces that sprite.

LEAD (vendored FFNx, checkout 2026-05-21 -- src/ff7_data.h "Display
battle damage" block + src/ff7/battle/animations.h opcode table):
  - animation-script opcode 0xC2 = "display damage" (and 0xF7 = "delay
    damage display effect") -- so damage display is driven from the
    per-actor ANIMATION script, not the damage calc directly.
  - ff7_externals.battle_sub_425D29        = gav(run_animation_script, 0x2850)
  - ff7_externals.battle_sub_425E5F        = gav(battle_sub_425D29, 0xA8)
  - ff7_externals.display_battle_damage_5BB410 = gav(battle_sub_425D29, 0x3D)
    (an effect60 function: animations.cpp checks effect60_array_fn[i] ==
    display_battle_damage_5BB410, and patches +0x1E2/+0x2D7 y-offset
    tables and +0x23F/+0x24C viewport words inside it -- so the body is
    at least ~0x2E0 long and does the actual digit/MISS drawing.)
  - FFNx naming convention: the _XXXXXX suffix IS the 1.02 US absolute
    address, and our 2013/2026 exes share those addresses (no ASLR).
  - run_animation_script = grc(battle_sub_42A5EB, 0xB8)  [ff7_data.h:797]
  - battle_anim_event (ff7.h) carries uint16_t damageEventQueueIdx --
    evidence that a DAMAGE EVENT QUEUE exists, filled at damage-calc
    time and consumed at display time. Its base/layout/flags are what
    this hunt must produce (the MISS encoding lives there or in the
    effect60 slot data).

PHASES (all offline, capstone over the exe ON DISK -- no game needed):
  1. Verify the FFNx chain byte-for-byte on our exe (every gav/grc hop
     must land on the address embedded in the FFNx name; a mismatch
     means the lead is bad and NOTHING later can be trusted).
  2. Disassemble the anim-script dispatch context around
     run_animation_script+0x2850 (which opcode installs 425D29) plus
     battle_sub_425D29 and battle_sub_425E5F in full. 425D29 is the
     ENQUEUE side: expect it to read the damage event queue and
     register display_battle_damage_5BB410 as an effect60 -- the
     queue's base address and field offsets fall out of this listing.
  3. Disassemble display_battle_damage_5BB410 in full (0x500 budget --
     FFNx patches prove >= 0x2E0). This is the CONSUMER: the branch
     that picks "MISS" glyphs over digits reveals the flag encoding
     (compare/test on the damage value or a flags field).
  4. Writer sweep: every .text site embedding 0x5BB410 as a 4-byte
     immediate = an enqueue site for the damage-display effect; every
     .text site embedding the queue base(s) found in phase 2 = a
     reader/WRITER of the damage event queue. The writers that are NOT
     inside 425D29/425E5F are the damage-calc side -- the moment the
     engine decides "this hit missed". Disassemble a window around
     every hit so the calling function and operand role (read vs
     write) are visible in one log.

OUTPUT: everything tees to a timestamped log next to this script
(standing rule: no manual copy-paste of console output).
"""
import sys, os, struct, datetime
import capstone

# ---------------------------------------------------------------------------
# Tee all print() output to a timestamped log (feedback-investigation-scripts
# rule: the log IS the deliverable; console is a convenience view).
# ---------------------------------------------------------------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_miss_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
_log = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s)
    _log.write(s)
    _log.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

# ---------------------------------------------------------------------------
# Load the exe from disk. Both installs carry the byte-identical ff7_en
# engine (confirmed 2026-07-08), so whichever is present is ground truth.
# ---------------------------------------------------------------------------
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

# PE section table -> VA-to-file-offset mapping. The exe is loaded at its
# preferred base (no ASLR on this binary), so file VAs are runtime VAs.
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
print(f"image base 0x{base:X}; .text VA 0x{text_lo:X}..0x{text_hi:X}\n")

def v2o(va):
    r = va - base
    for sva, svs, srp in secs:
        if sva <= r < sva + svs:
            return srp + (r - sva)
    return None

def grc(addr, offset):
    """FFNx get_relative_call: E8 rel32 at addr+offset -> callee VA."""
    off = v2o(addr + offset)
    if off is None or data[off] != 0xE8:
        return None
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return addr + offset + 5 + rel

def gav(addr, offset):
    """FFNx get_absolute_value: the u32 at addr+offset (operand immediate)."""
    return struct.unpack_from('<I', data, v2o(addr + offset))[0]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

# Annotated disassembly dump: every operand (mem disp or immediate) that
# lands in the game's static-data range gets a g_XXXXXX mark so queue
# bases and flag bytes jump out of the listing without hand-decoding.
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

# Byte-scan .text for a 4-byte little-endian constant. Finds the value in
# ANY operand role (push imm, mov disp, cmp imm, table entry) -- the
# v2.30.80 lesson: operand-FORM sweeps miss consumers; raw bytes don't.
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

# Disassemble a window around a raw hit so the enclosing instruction and
# its operand role (is the queue address a READ or a WRITE target?) are
# visible. Starting 0x20 early lets capstone resynchronize before the hit.
def dump_window(label, hit_va, before=0x20, after=0x28):
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

# ---------------------------------------------------------------------------
# PHASE 1: verify the FFNx chain on OUR exe. FFNx's name suffixes are the
# expected addresses; every hop must land exactly or the lead is invalid.
# ---------------------------------------------------------------------------
print("#" * 70)
print("# PHASE 1: FFNx chain verification")
print("#" * 70)
ras = grc(0x42A5EB, 0xB8)   # run_animation_script (ff7_data.h:797)
print(f"run_animation_script = grc(0x42A5EB,0xB8) = "
      f"{'0x%X' % ras if ras else 'FAIL'}")
sub_425D29 = gav(ras, 0x2850) if ras else None
print(f"battle_sub_425D29    = gav(ras,0x2850)    = 0x{sub_425D29:X} "
      f"(expect 0x425D29 -> {'OK' if sub_425D29 == 0x425D29 else 'MISMATCH'})")
disp_fn = gav(0x425D29, 0x3D)
print(f"display_battle_damage = gav(0x425D29,0x3D) = 0x{disp_fn:X} "
      f"(expect 0x5BB410 -> {'OK' if disp_fn == 0x5BB410 else 'MISMATCH'})")
sub_425E5F = gav(0x425D29, 0xA8)
print(f"battle_sub_425E5F    = gav(0x425D29,0xA8) = 0x{sub_425E5F:X} "
      f"(expect 0x425E5F -> {'OK' if sub_425E5F == 0x425E5F else 'MISMATCH'})")
print()

# ---------------------------------------------------------------------------
# PHASE 2: the enqueue side. Dispatch context first (which anim-script
# opcode reaches 425D29), then both subs in full. 425D29 runs 0x136 bytes
# up to 425E5F -- dump exactly that; 425E5F length unknown, budget 0x200.
# ---------------------------------------------------------------------------
print("#" * 70)
print("# PHASE 2: enqueue side -- dispatch context + battle_sub_425D29/425E5F")
print("#" * 70)
if ras:
    dump("run_animation_script @+0x2820..+0x28C0 (dispatch context for "
         "the 0x425D29 install; opcode compares should be visible)",
         ras + 0x2820, 0xA0, stop_at_ret=False)
dump("battle_sub_425D29 (damage-display trigger: reads the damage event "
     "queue, registers the effect60)", 0x425D29, 0x136, stop_at_ret=False)
dump("battle_sub_425E5F (companion display sub -- second value channel?)",
     0x425E5F, 0x200)

# ---------------------------------------------------------------------------
# PHASE 3: the consumer. display_battle_damage_5BB410 draws digits or the
# MISS glyph from the effect60 slot data -- the flag encoding is in its
# first branches. FFNx patches prove the body reaches +0x2D7; 0x500 budget
# with no ret-stop (big functions have early returns).
# ---------------------------------------------------------------------------
print("#" * 70)
print("# PHASE 3: consumer -- display_battle_damage_5BB410 in full")
print("#" * 70)
dump("display_battle_damage_5BB410", 0x5BB410, 0x500, stop_at_ret=False)

# ---------------------------------------------------------------------------
# PHASE 4a: every enqueue site of the display effect (push 0x5BB410).
# ---------------------------------------------------------------------------
print("#" * 70)
print("# PHASE 4a: .text sites embedding 0x5BB410 (effect60 enqueue sites)")
print("#" * 70)
for hit in scan_text_for_u32(0x5BB410):
    dump_window("imm 0x5BB410", hit)

# ---------------------------------------------------------------------------
# PHASE 4b: globals referenced by the enqueue side. Every static-data
# address 425D29/425E5F touches is a candidate piece of the damage event
# queue; sweep .text for each and dump windows -- the hits OUTSIDE the
# display functions are the damage-calc WRITERS we are hunting.
# ---------------------------------------------------------------------------
print("#" * 70)
print("# PHASE 4b: writer sweep over the enqueue side's globals")
print("#" * 70)
cands = set()
for fn_start, fn_len in ((0x425D29, 0x136), (0x425E5F, 0x200)):
    off = v2o(fn_start)
    for insn in md.disasm(data[off:off + fn_len], fn_start):
        if insn.id == 0:
            continue
        for op in insn.operands:
            d = None
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
            elif op.type == capstone.x86.X86_OP_IMM:
                d = op.imm & 0xFFFFFFFF
            if d is not None and 0x900000 <= d < 0xDE0000:
                cands.add(d)
print(f"candidate globals from 425D29/425E5F: "
      f"{', '.join('0x%X' % c for c in sorted(cands))}\n")
for c in sorted(cands):
    hits = scan_text_for_u32(c)
    print(f"### global 0x{c:X}: {len(hits)} .text hits")
    if len(hits) > 60:
        print("    (over 60 -- likely a shared/global counter, listing "
              "addresses only)")
        print("    " + ", ".join(f"0x{h:X}" for h in hits))
        print()
        continue
    for hit in hits:
        dump_window(f"g_0x{c:X}", hit)
print("DONE. Read the log top to bottom; the MISS flag encoding is in "
      "phase 3's first compare/test branches, the writers in phase 4b "
      "windows outside 0x425Dxx/0x5BB4xx.")
