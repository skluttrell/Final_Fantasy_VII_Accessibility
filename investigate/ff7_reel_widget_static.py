#!/usr/bin/env python3
"""
ff7_reel_widget_static.py -- decode the EXECUTION-TIME limit reel/slot
minigame (Tifa's Yeah!/Hit!/Miss reels, Cait Sith's Slots), 2026-08-09.

USER DECISION (this session): ship BOTH accessibility methods for the
reels -- positional timing tones (DEFAULT) and spoken stop results --
behind a config option.  This script is the part-2 static pass that has
to find the live state those features will read.

WHY THE MENU-SIDE .98/.106 WORK CANNOT SEE THE REELS: log.12 shows
BMENU state 27 -> 0xFFFF (closed) BEFORE the limit executes -- the
minigame runs while the menu state machine is parked.  The .106
handlers (fn[26]/fn[27]) are only confirm/cancel wrappers.

FFNx NAMES THE MACHINERY (vendored source, the v2.30.100 lesson --
check the framework FIRST):
  - ff7_data.h:1181:  display_tifa_slots_handler_6E3135 =
        get_relative_call(display_battle_menu_6D797C, 0x1C2)
    => the reel DISPLAY runs inside the battle menu's per-frame draw
       0x6D797C even while the state machine is closed.  VA 0x6E3135.
  - animations.cpp:1324 "Tifa slots speed patch": patches +0x168
    (an `and ..., 7` -> 7 becomes 3) and +0x16B in that handler for
    60fps -- i.e. the spin-phase divider lives at +0x168.  A 50ms
    poll concern can be answered by reading this divider's semantics.
  - ff7_data.h:936: run_tifa_limit_effects =
        get_relative_call(battle_sub_4E1627, 0xD); the 1-2 / 2-1
    effect mains + subs hang off it (effect100 fns) -- the DAMAGE
    side of the reel results.

KNOWN GOING IN (.98 dump 20260809_133041 + .106):
  - fn[27] 0x6DA795 (Tifa) / fn[26] 0x6DA898 (Cait) confirm via phase
    helpers 0x6E3101 / 0x6E2143 == 2, then call 0x6E3724 / 0x6E2FA9
    before issuing -- those callees are the widget SETUP suspects.
  - The .98 sweep caught an untraced init run writing constants into
    WIDGET_BASE+0x6C8..+0x6FC (0xDC2768..0xDC279C, writer ~0x6D8A7B)
    and refs to WIDGET_BASE+0x1C0 (0xDC2260) -- reel-state suspects.

WHAT THIS SCRIPT ANSWERS (offline, exe file only):
  1. Full annotated listing of display_tifa_slots_handler_6E3135:
     which statics hold the spin position / current reel / stop
     results, where the FFNx speed patch lands, and whether the
     handler itself polls input (0x6F53F1) to stop a reel.
  2. The call-site gate in display_battle_menu_6D797C around +0x1C2:
     what flag activates the reel display -- that flag is the mod's
     "reels are live" signal.
  3. Phase helpers + confirm-side setup callees, and the 0x6D8A7B
     init writer: the reel struct's initial values (reel count,
     symbol layout hints).
  4. Sweep: every .text reference to each static the display handler
     touches -- finds the stop-input site, the result consumer that
     feeds the damage pipeline, and any second (Cait Sith) display
     handler sharing the struct.

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_reel_widget_static.py
"""
import sys, os, struct, datetime

# --- tee all output to a timestamped log (standing rule: never require
# --- manual copy-paste of investigation output) ------------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"reel_widget_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

def v2o(va):
    r = va - image_base
    for _, sva, svs, srs, sro in secs:
        if sva <= r < sva + max(svs, srs):
            fo = sro + (r - sva)
            return fo if fo < len(data) else None
    return None

def text_bounds():
    for name, sva, svs, srs, sro in secs:
        if name == '.text':
            return image_base + sva, image_base + sva + srs, sro
    return None

# --- known-global annotator --------------------------------------------
KNOWN = {
    0x91EF9C: "BATTLE_MENU_STATE",
    0x91EF98: "BATTLE_MENU_PREV_STATE",
    0xDC3C7C: "BATTLE_ACTIVE_SLOT",
    0xDC3C80: "BATTLE_ACTIVE_SLOT2",
    0xDC35AC: "BATTLE_MENU_BUSY",
    0xDC35A4: "BATTLE_LIMIT_COUNT",
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
    0x745160: "sfx_3arg (fn[27] cancel path)",
    0x6D797C: "display_battle_menu (FFNx)",
    0x6E3135: "display_tifa_slots_handler (FFNx)",
    0x6E3101: "tifa_phase_helper (fn[27])",
    0x6E2143: "cait_phase_helper (fn[26])",
    0x6E3724: "tifa_confirm_setup (fn[27])",
    0x6E2FA9: "cait_confirm_setup (fn[26])",
    0x41963C: "get_kernel_text",
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
                continue
            if 0xDC20A0 <= v < 0xDC20A0 + 0x700:
                notes.append(f"WIDGET_BASE+0x{v-0xDC20A0:X}")
            elif 0xDBA498 <= v < 0xDBA498 + 0x440:
                notes.append(f"CHAR_BLOCK+0x{v-0xDBA498:X}")
    return ("   ; " + ", ".join(notes)) if notes else ""

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def disasm_listing(fva, window=0x1800, label="", collect_statics=None):
    """Full annotated listing.  Optionally collects every absolute
    static address (mem disp or imm) in 0x900000..0xE00000 (BSS/data
    band) into collect_statics for the later cross-ref sweep."""
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
        if collect_statics is not None:
            for op in insn.operands:
                v = None
                if op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
                    v = op.mem.disp & 0xFFFFFFFF
                elif op.type == capstone.x86.X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                if v is not None and 0x900000 <= v < 0xE00000:
                    collect_statics.add(v)
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8s} {insn.op_str}"
              f"{annotate(insn)}")
        if insn.mnemonic == 'ret' and insn.address >= max_target:
            break
        if insn.mnemonic == 'int3':
            break
    return calls

def find_fn_start(va, back=0x200):
    """Scan backwards for the nearest `push ebp; mov ebp, esp` prologue."""
    off = v2o(va)
    for d in range(back):
        o = off - d
        if data[o] == 0x55 and data[o+1] == 0x8B and data[o+2] == 0xEC:
            return va - d
    return va

# ======================================================================
# 1. The reel display handler -- THE target.  Collect every static it
#    touches for the sweep in step 4.
# ======================================================================
reel_statics = set()
calls_disp = disasm_listing(0x6E3135, window=0x1000,
                            label="display_tifa_slots_handler (FFNx name; "
                                  "speed patch @ +0x168/+0x16B)",
                            collect_statics=reel_statics)

# ======================================================================
# 2. The call-site gate: display_battle_menu_6D797C around +0x1C2.
#    Disassemble the whole leading stretch so the gating conditions
#    (which flag selects the tifa-slots call) are readable.
# ======================================================================
disasm_listing(0x6D797C, window=0x400,
               label="display_battle_menu head (call to 0x6E3135 at +0x1C2; "
                     "read the branch conditions choosing it)")

# ======================================================================
# 3. Confirm-side setup + phase helpers + the .98 sweep's untraced init
# ======================================================================
for va, lbl in [
    (0x6E3101, "tifa_phase_helper (fn[27] gates OK on ==2)"),
    (0x6E2143, "cait_phase_helper (fn[26] gates OK on ==2)"),
    (0x6E3724, "tifa_confirm_setup (called by fn[27] before issuing)"),
    (0x6E2FA9, "cait_confirm_setup (called by fn[26] before issuing)"),
]:
    disasm_listing(va, window=0x600, label=lbl, collect_statics=reel_statics)

init_start = find_fn_start(0x6D8A7B)
disasm_listing(init_start, window=0x300,
               label=f"init writer of WIDGET+0x6C8..+0x6FC "
                     f"(fn start resolved from 0x6D8A7B)",
               collect_statics=reel_statics)

# The effect side (damage consumer of the reel results) -- reference
# listings so the log carries them for the feature session.
run_tifa = None
o = v2o(0x4E1627 + 0xD)
if data[o] == 0xE8:   # get_relative_call replica
    run_tifa = (0x4E1627 + 0xD + 5 + struct.unpack_from('<i', data, o+1)[0]) & 0xFFFFFFFF
    print(f"\nrun_tifa_limit_effects (FFNx chain) = 0x{run_tifa:X}")
    disasm_listing(run_tifa, window=0x300,
                   label="run_tifa_limit_effects (FFNx: battle_sub_4E1627+0xD)")

# ======================================================================
# 4. Cross-ref sweep: every .text reference to every static the reel
#    machinery touches.  Readers = draw/result consumers; writers =
#    spin advance, stop-input site, init.  (v2.30.80 lesson: statics
#    are addressed as absolute dword immediates/disps.)
# ======================================================================
# Drop the ubiquitous shared globals so the sweep stays readable:
for noise in (0x91EF9C, 0x91EF98, 0xDC3C7C, 0xDC3C80, 0xDC35AC, 0xDC3C70,
              0xDC3C74, 0xDC3C78, 0xDC3C90, 0xDC3C94, 0xDC3C98, 0x9A889A):
    reel_statics.discard(noise)

t0, t1, troff = text_bounds()
print("\n" + "=" * 76)
print(f"===== .text cross-ref sweep over {len(reel_statics)} reel-machinery "
      f"statics")
print("=" * 76)
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
        if v in reel_statics:
            hits.setdefault(v, []).append(
                (insn.address, f"{insn.mnemonic} {insn.op_str}"))
for v in sorted(hits):
    refs = hits[v]
    tag = ""
    if 0xDC20A0 <= v < 0xDC20A0 + 0x700:
        tag = f"  (WIDGET_BASE+0x{v-0xDC20A0:X})"
    elif 0xDBA498 <= v < 0xDBA498 + 0x440:
        tag = f"  (CHAR_BLOCK+0x{v-0xDBA498:X})"
    print(f"\n0x{v:08X}{tag} ({len(refs)} refs):")
    for a, txt in refs[:16]:
        print(f"  0x{a:08X}  {txt}")
    if len(refs) > 16:
        print(f"  ... {len(refs)-16} more")

print(f"\nLog saved to: {_log_path}")
