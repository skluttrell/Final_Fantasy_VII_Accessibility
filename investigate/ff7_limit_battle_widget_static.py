#!/usr/bin/env python3
"""
ff7_limit_battle_widget_static.py -- decode the IN-BATTLE limit-select
widget (BATTLE_MENU_STATE 24), 2026-08-09.

USER REQUEST: after confirming the Limit command in battle, the game
opens a small "LIMIT LEVEL n / <technique>" selection window
(Screenshots/BattleScreen/limit_break_selection_1.jpg shows "LIMIT
LEVEL 1 / Braver").  BattleMenuThread announces the command grid and
the item/magic/summon lists, but state 24 has NO announce branch --
the limit list is silent.

KNOWN GOING IN (research doc S4 + v2.9/v2.36 derivations):
  - BATTLE_MENU_FN_TABLE 0x91E6B8 = uint32[64] per-state handlers.
    fn[24] = the limit-select widget handler ("0x18" in the v2.9 note).
    fn[26]/fn[27] were flagged "Cait/Tifa slots" (special limit UIs) --
    dumped here too for completeness but NOT this session's target.
  - Per-slot widget blocks at 0xDC20A0 + slot*0x700, 0x38-byte widget
    structs (+0 horiz, +4 vert, +0x14 scroll, +0x1C total entries);
    known widgets sit at +0x00 (command) +0x38 (item) +0x70 (magic)
    +0xA8 (summon).  The limit widget's offset is UNKNOWN.
  - Per-slot char data at 0xDBA498 + slot*0x440 (command table +0x4C,
    magic list +0x108, summon list +0x2C8).  Where the limit ENTRIES
    live is UNKNOWN.
  - Confirm flow writes: issued cmd u8 0xDC3C70, action u16 0xDC3C78.
    Live-verified (v2.30.77): a confirmed limit's flash idx IS the
    0-based kernel index (Braver idx=0 -> magic entry 128+0), so if
    the list entry byte is that same idx, ResolveActionName(0x14, idx)
    resolves the spoken name with ZERO new name machinery.

WHAT THIS SCRIPT ANSWERS (all offline -- exe file only, game not run):
  1. fn[24]'s address, full annotated listing, one call level deep for
     small helpers (the 0x6F4DB2 nav-helper CALL's widget-pointer
     argument IS the widget offset -- same trick as the v2.36 session).
  2. The limit LIST TABLE: whatever [table + index*stride] read feeds
     the Confirm write to 0xDC3C78 is the entry array (address, stride,
     width, empty marker).
  3. Cross-check: who else references that table (the builder that
     populates it when Limit opens, the draw code) -- via a full .text
     immediate-operand sweep, the v2.30.80 lesson (sweep for base+off
     AS A DWORD IMMEDIATE, engine addresses statics absolutely).

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_limit_battle_widget_static.py
"""
import sys, os, struct, datetime

# --- tee all output to a timestamped log (standing rule: never require
# --- manual copy-paste of investigation output) ------------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"limit_battle_widget_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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
        # use the RAW size for the readable span -- .data's virtual size
        # extends past the file-backed bytes (BSS tail)
        if sva <= r < sva + max(svs, srs):
            fo = sro + (r - sva)
            return fo if fo < len(data) else None
    return None

def text_bounds():
    for name, sva, svs, srs, sro in secs:
        if name == '.text':
            return image_base + sva, image_base + sva + srs, sro
    return None

# --- known-global annotator: makes the listings self-explanatory -------
KNOWN = {
    0x91EF9C: "BATTLE_MENU_STATE",
    0x91EF98: "BATTLE_MENU_PREV_STATE",
    0xDC3C7C: "BATTLE_ACTIVE_SLOT",
    0xDC35AC: "BATTLE_MENU_BUSY",
    0xDC3C70: "BATTLE_ISSUED_CMD",
    0xDC3C74: "issued_action_type",
    0xDC3C78: "BATTLE_ISSUED_ACTION",
    0xDC3C90: "BATTLE_TARGET_TYPE",
    0xDC3C94: "BATTLE_TARGET_INDEX",
    0xDC3C98: "BATTLE_TARGETING_ACTOR",
    0xDC20A0: "BATTLE_WIDGET_BASE",
    0xDBA498: "BATTLE_CHAR_BLOCK",
    0x9A889A: "input word (v2.9)",
    0x6F4DB2: "widget_nav_helper",
    0x6F53F1: "input_check_thunk",
    0x74580A: "cursor_sfx",
}
def annotate(insn):
    """Append '; NAME[+off]' notes for any absolute address operand that
    lands inside a known global/struct so the listing reads itself."""
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
                continue
            # inside the widget block (any slot-0 widget field)?
            if 0xDC20A0 <= v < 0xDC20A0 + 0x700:
                notes.append(f"WIDGET_BASE+0x{v-0xDC20A0:X}")
            elif 0xDBA498 <= v < 0xDBA498 + 0x440:
                notes.append(f"CHAR_BLOCK+0x{v-0xDBA498:X}")
    return ("   ; " + ", ".join(notes)) if notes else ""

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def disasm_listing(fva, window=0x1800, label=""):
    """Full annotated listing; returns the call targets encountered.
    Stops at the first ret not jumped over (same heuristic as the
    submenu-disasm session -- good enough for these small handlers)."""
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

# ======================================================================
# 1. fn table: resolve the state 24/26/27 handlers
# ======================================================================
FN_TABLE = 0x91E6B8
fn = [struct.unpack_from('<I', data, v2o(FN_TABLE) + i*4)[0] for i in range(64)]
print("\nfn table (states 0..31):")
for i in range(0, 32, 4):
    print("  " + "  ".join(f"[{j:2d}]=0x{fn[j]:08X}" for j in range(i, i+4)))

H24, H26, H27 = fn[24], fn[26], fn[27]
print(f"\nstate-24 (limit select) handler = 0x{H24:X}")
print(f"state-26 handler = 0x{H26:X}   state-27 handler = 0x{H27:X}"
      f"   (Cait/Tifa special widgets -- reference only)")

# ======================================================================
# 2. full listing of fn[24] + one level of small callees
# ======================================================================
calls24 = disasm_listing(H24, label="fn[24] -- limit-select widget handler")

seen = {H24, 0x6F4DB2, 0x6F53F1, 0x74580A}   # shared helpers already mapped
for c in dict.fromkeys(calls24):
    if c in seen:
        continue
    seen.add(c)
    disasm_listing(c, window=0x800, label=f"callee of fn[24]")

# reference listings for the special widgets (not this session's target,
# but free while we're here -- they land in the log for a future pass)
disasm_listing(H26, window=0x800, label="fn[26] -- special limit widget A")
disasm_listing(H27, window=0x800, label="fn[27] -- special limit widget B")

# ======================================================================
# 3. .text sweep: who references the addresses fn[24] touches?
#    (run AFTER reading the listing above -- the sweep below covers the
#    widget-block band and char-block band generically so the log holds
#    the cross-references no matter which offsets step 2 reveals)
# ======================================================================
t0, t1, troff = text_bounds()
print("\n" + "=" * 76)
print("===== .text sweep: absolute refs into slot-0 widget block "
      "(0xDC20A0..+0x700)\n===== and slot-0 char block (0xDBA498..+0x440) "
      "outside already-known offsets")
print("=" * 76)
# Known/expected offsets to mute so the interesting rows stand out:
#   widget +0x00/+0x38/+0x70/+0xA8 blocks (0x38 bytes each) = mapped
#   char   +0x4C..+0xC4 command table band, +0x108 magic, +0x2C8 summon
code = data[troff:troff + (t1 - t0)]
hits = {}
for insn in md.disasm(code, t0):
    if insn.id == 0:
        continue
    for op in insn.operands:
        v = None
        if op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
            v = op.mem.disp & 0xFFFFFFFF
        elif op.type == capstone.x86.X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
        if v is None:
            continue
        if 0xDC20A0 <= v < 0xDC20A0 + 0x700:
            base, name = 0xDC20A0, "WIDGET"
        elif 0xDBA498 <= v < 0xDBA498 + 0x440:
            base, name = 0xDBA498, "CHAR"
        else:
            continue
        off_in = v - base
        # mute the four mapped widget structs and the mapped char bands
        if name == "WIDGET" and off_in < 0xA8 + 0x38:
            continue
        if name == "CHAR" and (0x00 <= off_in < 0x108 + 8*8 or
                               0x2C8 <= off_in < 0x2C8 + 8*8):
            continue
        hits.setdefault((name, off_in), []).append(
            (insn.address, f"{insn.mnemonic} {insn.op_str}"))
for (name, off_in), refs in sorted(hits.items()):
    print(f"\n{name}+0x{off_in:X} ({len(refs)} refs):")
    for a, txt in refs[:12]:
        print(f"  0x{a:08X}  {txt}")
    if len(refs) > 12:
        print(f"  ... {len(refs)-12} more")

print(f"\nLog saved to: {_log_path}")
