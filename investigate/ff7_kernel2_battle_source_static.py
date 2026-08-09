#!/usr/bin/env python3
"""
ff7_kernel2_battle_source_static.py -- find the game's OWN in-battle
kernel2 text source, 2026-08-09.

USER REPORT (old_game_logs/2013_with_7h/local_run/ffvii_accessibility.log.10):
junk speech on limit-break name upgrades -- "Aerith, +,+ ((((((%%%% ..."
(12:19:52 gen=135, flash cmd=0x14 idx=14 ok=1) and "Cloud, (+../-!#...."
(12:21:01 gen=161 AND 12:38:02 gen=243, both flash idx=0 = Braver,
ok=1).  The junk is IDENTICAL across battles => a STABLE bad source,
not a race.  Same log, same section base all session: the kernel2 heap
scan latched magic=0x2F846258 at 11:57:55 and every magic name BELOW
entry 128 (Ice/Bolt/Cure/Fire) resolved correctly from it all session,
while every LIMIT name (entries 128+) decoded binary garbage -- byte
values 0x02..0x0F (FF7-encoded '"#$%()+,-./') in bitmap-looking rows.
The v2.30.77 SectionBodyPlausible check passed (offset table monotone,
in band) because the TABLE survived; only the TEXT BYTES past the
early entries are rotten -- most likely the heap block is a partial /
truncated copy and the high entry offsets dereference past its end
into a neighboring allocation (IsReadableSpan passes: committed heap).

THE CONTRADICTION THIS SCRIPT RESOLVES: v2.7 (2026-07-11) probed the
game's static text scratch 0x9A13C8 live during battle and found it
ALL ZERO, concluded "battle never populates it", and built the heap
signature scan instead.  But v2.30.98's static session proved the
IN-BATTLE limit-select window (draw 0x6DF40D) feeds
get_kernel_text(section 3, id) -- and the user's screenshot shows the
window drawing "Braver" correctly IN BATTLE.  Both cannot be true
unless the scratch is populated lazily / at a specific moment, or
section 3 takes a different path than the generic scratch read.  If
the game has an authoritative in-battle source, the mod should read
THAT (validated), not a scavenged heap copy.

KNOWN GOING IN (research doc S4):
  0x41963C  get_kernel_text(section, idx, 8) -- FFNx external; result
            historically -> 0xDC208C (dead under FFNx; FFNx replaces
            the flash-text CONSUMER, but game draw code still CALLS
            get_kernel_text directly, e.g. 0x6DF40D).
  0x419457  kernel2_get_text: base = 0x9A13C8 + u16[0x9A7FC8+file*2];
            text = base + u16[base + idx*2]   (the generic path)
  0x419A38  per-section jump table inside get_kernel_text; sections
            6..9 = BATTLE statics (target names, enemy-attack names
            0x9A9484 etc.) -- so SOME sections bypass the scratch.
  0x6DF40D  battle limit window draw: get_kernel_text(3, table[i]),
            names biased +128 (v2.30.98).

WHAT THIS SCRIPT ANSWERS (all offline -- exe file only, game not run):
  1. get_kernel_text full annotated listing: exactly which sections go
     through the 0x9A13C8 scratch and which use battle statics.
  2. The 0x9A7FC8 u16 offset table's INITIAL FILE BYTES: if it is
     initialized .data (fixed per-section offsets), the scratch layout
     is compile-time fixed and section 3's base is a known constant.
  3. Every .text reference to 0x9A13C8 and 0x9A7FC8 (raw 4-byte scan =
     catches both imm and disp operands, the v2.30.80 lesson), with a
     disasm window around each hit, classified read vs write -- the
     WRITERS are the section loader(s); their call sites say WHEN the
     scratch is (re)populated and whether battle ever runs one.
  4. The loader function's full listing (walked back to its prologue)
     so the population mechanism is understood, not guessed.

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_kernel2_battle_source_static.py
"""
import sys, os, struct, datetime

# --- tee all output to a timestamped log (standing rule: never require
# --- manual copy-paste of investigation output) ------------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_battle_source_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
]
exe_path = next((c for c in EXE_CANDIDATES if os.path.isfile(c)), None)
if exe_path is None:
    print("ERROR: ff7_en.exe not found in any candidate path")
    sys.exit(1)
data = open(exe_path, 'rb').read()
print(f"Loaded exe: {exe_path} ({len(data)} bytes)")

# --- minimal PE section map so VAs resolve to file offsets -------------
pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    name = data[s:s+8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((name, va, vs, rs, ro))
    print(f"  section {name:<8s} va=0x{image_base+va:08X} vsz=0x{vs:X} raw=0x{rs:X}")

def v2o(va):
    r = va - image_base
    for _, sva, svs, srs, sro in secs:
        if sva <= r < sva + max(svs, srs):
            fo = sro + (r - sva)
            return fo if fo < len(data) else None
    return None

def v2o_raw(va):
    """File offset ONLY if the VA is file-backed (inside raw size) --
    BSS reads must come back None, not garbage from the next section."""
    r = va - image_base
    for _, sva, svs, srs, sro in secs:
        if sva <= r < sva + srs:
            fo = sro + (r - sva)
            return fo if fo < len(data) else None
    return None

def text_bounds():
    for name, sva, svs, srs, sro in secs:
        if name == '.text':
            return image_base + sva, image_base + sva + srs, sro
    return None

SCRATCH   = 0x9A13C8   # kernel2 text scratch (v2.7: "ALL ZERO in battle")
OFFTAB    = 0x9A7FC8   # u16 per-file offset table into the scratch
GKT       = 0x41963C   # get_kernel_text(section, idx, 8)
K2GT      = 0x419457   # kernel2_get_text (generic scratch path)
JMPTAB    = 0x419A38   # get_kernel_text per-section jump table
LIMITDRAW = 0x6DF40D   # battle limit window draw (calls GKT(3, id))

KNOWN = {
    SCRATCH:  "K2_SCRATCH(0x9A13C8)",
    OFFTAB:   "K2_OFFTAB(0x9A7FC8)",
    GKT:      "get_kernel_text",
    K2GT:     "kernel2_get_text",
    0xDC208C: "GKT_result_ptr",
    0x9A9484: "ENEMY_ATTACK_NAME_TABLE",
    0x9A8794: "BATTLE_FORMATION_SLOTS",
    0x9A8E9C: "scene_enemy_records",
    0x9A80F0: "target_name_scratch",
    0xDB9584: "savemap_charrec_area?",
}
def annotate(insn):
    notes = []
    for op in insn.operands:
        vals = []
        if op.type == capstone.x86.X86_OP_IMM:
            vals.append(op.imm & 0xFFFFFFFF)
        elif op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
            vals.append(op.mem.disp & 0xFFFFFFFF)
        for v in vals:
            if v in KNOWN:
                notes.append(KNOWN[v])
            elif SCRATCH <= v < SCRATCH + 0x7000:
                notes.append(f"K2_SCRATCH+0x{v-SCRATCH:X}")
            elif OFFTAB <= v < OFFTAB + 0x40:
                notes.append(f"K2_OFFTAB+0x{v-OFFTAB:X}")
    return ("   ; " + ", ".join(notes)) if notes else ""

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def disasm_listing(fva, window=0x600, label=""):
    off = v2o(fva)
    if off is None:
        print(f"!! cannot map 0x{fva:X}")
        return []
    calls = []
    max_target = fva
    print()
    print("=" * 76)
    print(f"===== 0x{fva:08X}  {label}")
    print("=" * 76)
    for insn in md.disasm(data[off:off+window], fva):
        if insn.id == 0:
            continue
        if insn.group(capstone.CS_GRP_JUMP):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM and \
                   fva < op.imm < fva + window:
                    max_target = max(max_target, op.imm)
        if insn.mnemonic == 'call':
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM and \
                   0x400000 <= op.imm < 0x800000:
                    calls.append(op.imm)
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8s} {insn.op_str}"
              f"{annotate(insn)}")
        if insn.mnemonic == 'ret' and insn.address >= max_target:
            break
        if insn.mnemonic == 'int3':
            break
    return calls

def func_start(va, max_back=0x2000):
    """Walk back to a plausible function prologue: the byte AFTER a
    run of int3/ret padding, or a push-ebp/mov-ebp,esp pair.  Coarse
    but effective on this compiler's output (same heuristic family as
    earlier sessions)."""
    off = v2o(va)
    if off is None:
        return va
    o = off
    while o > off - max_back and o > 0:
        b = data[o-1]
        if b in (0xCC, 0xC3):          # int3 padding / ret of previous fn
            # step forward over any additional padding
            while data[o] == 0xCC:
                o += 1
            return va - (off - o)
        o -= 1
    return va - (off - o)

# ======================================================================
# 1. get_kernel_text + kernel2_get_text full listings
# ======================================================================
print("\n\n#### 1. get_kernel_text (0x41963C) -- which sections use the scratch?")
disasm_listing(GKT, window=0x800, label="get_kernel_text(section, idx, 8)")
print("\n#### kernel2_get_text (0x419457) -- the generic scratch path")
disasm_listing(K2GT, window=0x200, label="kernel2_get_text(file, idx)")

# the per-section jump table itself
print("\n#### get_kernel_text section jump table @ 0x419A38")
jo = v2o(JMPTAB)
if jo is not None:
    for i in range(16):
        tgt = struct.unpack_from('<I', data, jo + i*4)[0]
        if not (0x400000 <= tgt < 0x800000):
            print(f"  [section {i:2d}] 0x{tgt:08X}  (out of .text -- table ends?)")
            break
        print(f"  [section {i:2d}] handler 0x{tgt:08X}")

# ======================================================================
# 2. the offset table's initial file bytes -- fixed layout or runtime?
# ======================================================================
print("\n\n#### 2. K2_OFFTAB (0x9A7FC8) initial file bytes")
to = v2o_raw(OFFTAB)
if to is None:
    print("  0x9A7FC8 is BSS (not file-backed) => table is RUNTIME-FILLED."
          "\n  => scratch layout is set by the loader, not the compiler;"
          "\n     the writer sweep below finds who fills it.")
else:
    vals = struct.unpack_from('<16H', data, to)
    print("  file-backed values (u16 x16):")
    print("   " + " ".join(f"{v:04X}" for v in vals))
    if any(vals):
        print("  NONZERO => compile-time fixed layout: section N base ="
              " 0x9A13C8 + table[N] -- a known constant per section.")
    else:
        print("  all zero in file => runtime-filled despite being"
              " file-backed; see writer sweep.")
so = v2o_raw(SCRATCH)
print(f"  scratch 0x9A13C8 file-backed: {'yes' if so is not None else 'no (BSS)'}")

# ======================================================================
# 3. raw 4-byte scan of .text for BOTH constants (imm or disp)
# ======================================================================
print("\n\n#### 3. .text references to the scratch and the offset table")
tb = text_bounds()
if tb is None:
    print("!! no .text section"); sys.exit(1)
tstart_va, tend_va, tro = tb
tsz = tend_va - tstart_va

def sweep(const, name):
    """Find every 4-byte LE occurrence of `const` in .text, then disasm
    a window straddling each hit so the actual instruction (and whether
    it READS or WRITES) is visible.  Returns hit VAs."""
    pat = struct.pack('<I', const)
    hits = []
    idx = data.find(pat, tro, tro + tsz)
    while idx != -1:
        hits.append(tstart_va + (idx - tro))
        idx = data.find(pat, idx + 1, tro + tsz)
    print(f"\n-- {name} (0x{const:08X}): {len(hits)} raw hits in .text")
    for h in hits:
        # disasm from a bit before the constant so the owning instruction
        # decodes; print the few instructions covering the hit
        start = h - 0x10
        off = v2o(start)
        if off is None:
            continue
        printed = 0
        for insn in md.disasm(data[off:off+0x30], start):
            if insn.id == 0:
                continue
            if insn.address <= h < insn.address + insn.size:
                # classify: does a mem operand with this disp get written?
                verb = "?"
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_MEM and \
                       (op.mem.disp & 0xFFFFFFFF) == const:
                        verb = "WRITE" if (op.access & capstone.CS_AC_WRITE) \
                               else "read"
                    elif op.type == capstone.x86.X86_OP_IMM and \
                         (op.imm & 0xFFFFFFFF) == const:
                        verb = "imm (address taken)"
                print(f"  0x{insn.address:08X}  {insn.mnemonic:<8s} "
                      f"{insn.op_str}   [{verb}]{annotate(insn)}")
                printed += 1
                break
        if not printed:
            print(f"  0x{h:08X}  (hit inside data/unaligned -- not an"
                  f" instruction operand start)")
    return hits

hits_tab     = sweep(OFFTAB,  "K2_OFFTAB")
hits_scratch = sweep(SCRATCH, "K2_SCRATCH")

# also catch table element accesses addressed as OFFTAB+2/+4/... (a
# loader may write entries individually) and scratch interior bases
extra = []
for base, name, span in ((OFFTAB, "K2_OFFTAB", 0x20),):
    for delta in range(2, span, 2):
        pat = struct.pack('<I', base + delta)
        idx = data.find(pat, tro, tro + tsz)
        while idx != -1:
            extra.append((tstart_va + (idx - tro), base + delta, name, delta))
            idx = data.find(pat, idx + 1, tro + tsz)
print(f"\n-- interior K2_OFFTAB element refs (+2..+0x1E): {len(extra)} hits")
for h, const, name, delta in extra:
    start = h - 0x10
    off = v2o(start)
    if off is None:
        continue
    for insn in md.disasm(data[off:off+0x30], start):
        if insn.id == 0:
            continue
        if insn.address <= h < insn.address + insn.size:
            print(f"  0x{insn.address:08X}  {insn.mnemonic:<8s} {insn.op_str}"
                  f"   [{name}+0x{delta:X}]{annotate(insn)}")
            break

# ======================================================================
# 4. writers: list the owning function of every WRITE / address-taken hit
# ======================================================================
print("\n\n#### 4. owning functions of scratch/table references")
all_hits = sorted(set(hits_tab + hits_scratch + [h for h, *_ in extra]))
seen_fns = set()
for h in all_hits:
    fs = func_start(h)
    if fs in seen_fns:
        continue
    seen_fns.add(fs)
    print(f"\n-- function ~0x{fs:08X} (contains ref at 0x{h:08X})")
    disasm_listing(fs, window=min(0x700, (h - fs) + 0x400),
                   label=f"owner of kernel2 scratch/table ref @0x{h:08X}")

# ======================================================================
# 5. cross-check: the battle limit draw's GKT call (v2.30.98 anchor)
# ======================================================================
print("\n\n#### 5. battle limit draw 0x6DF40D -- confirm the GKT(3, id) call")
disasm_listing(LIMITDRAW, window=0x400, label="battle limit window draw")

print("\nDone.")
