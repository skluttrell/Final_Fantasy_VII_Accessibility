#!/usr/bin/env python3
"""
ff7_battle_menu_static.py -- Static resolution + disassembly of the battle
COMMAND-MENU state machine in ff7_en.exe (on disk), hunting the battle
menu cursor that survived three live-scanning investigation sessions.

WHY THIS APPROACH (2026-07-12)
------------------------------
The battle-menu-cursor problem was previously attacked with live memory
scanning only, and every technique failed for a documented reason:
  - full-heap delta scans: ~1.5M bytes of background churn per quiet
    window drowned the signal (Research doc section 14, technique 5);
  - hardware breakpoints: the game self-terminates (anti-debug);
  - the two known per-actor battle arrays (0xBE1178 / 0xBF23B8) were
    exhaustively checked -- the cursor is NOT in either.

But the two techniques that now sit at the TOP of the success ranking
(static chain resolution against the exe on disk, and struct/architecture
matching) were only developed AFTER those sessions stalled. Applying them
now, the vendored FFNx source turns out to already map the entire battle
menu architecture:

    ff7_data.h:174  battle_menu_update_6CE8B3 = grc(battle_main_loop, 0x368)
    ff7_data.h:175  battle_sub_6DB0EE         = grc(battle_menu_update, 0xD9)
    ff7_data.h:178  battle_menu_state_fn_table = gav(battle_sub_6DB0EE, 0x1B4)
                                                  -- span of 64 entries
    ff7_data.h:729  handle_actor_ready  = fn_table[0]
    ff7_data.h:730  battle_menu_state   = (WORD*)gav(handle_actor_ready, 0x17B)

This is EXACTLY the architecture the PSX decomp predicted for the PC port
(Research doc: "a small menu-widget struct selected by a 'current widget'
global"): battle_menu_state is the current-widget selector, and the
64-entry function table holds one update handler per widget/state.
Known state meanings from FFNx usage:
    state 0      = actor ready (command menu opens)     [ff7_data.h:729]
    states 0..18 = command/sub-menu phase (auto-attack gate in
                   ff7/menu.cpp:149 fires while state < 19)
    state 19     = targeting (set_battle_targeting_data resolved from
                   fn_table[19])                        [ff7_data.h:733]
    state 26     = Cait Sith slots (sfx.cpp:769)

The cursor indices we want for TTS (command row, magic/item list row,
target selection) MUST be read/written inside these handlers -- a state
handler that responds to Up/Down does `inc/dec [global]` (or add/sub 1)
on its cursor variable. So instead of scanning 1.5M churning heap bytes
live, we disassemble ~30 small known-code functions offline and collect
every absolute-address global they mutate. That candidate list (expected:
dozens, not thousands) then feeds a targeted live verify pass.

WHY THE ANCHOR IS TRUSTWORTHY WITHOUT battle_main_loop
------------------------------------------------------
FFNx resolves battle_main_loop from a live game object at runtime, which
we can't replicate on disk. But FFNx's own symbol NAMES embed the US-1.02
virtual addresses (battle_menu_update_6CE8B3, battle_sub_6DB0EE,
battle_update_targeting_info_6E6291, targeting_actor_id_DC3C98), and the
2026 rerelease exe is confirmed address-identical to that build (memory:
project-ffvii-2026-access). So we anchor directly at 0x6CE8B3 and the
chain SELF-VALIDATES three independent ways:
    grc(0x6CE8B3, 0xD9)  must equal 0x6DB0EE
    grc(0x6DB0EE, 0x1F9) must equal 0x6E6291
    gav(0x6E6291, 0x684) must equal 0xDC3C98
If all three land, every other value read off the same chain is trusted
exactly as much as FFNx itself.

WHY STATIC FILE ANALYSIS (not live memory)
------------------------------------------
Same reasoning as ff7_wall_nav_static.py: FFNx trampolines battle
functions at runtime (battle_menu_update+0xD9 call IS one of its
replace_call_function targets, ff7_opengl.cpp:357), so live code bytes
can be FFNx's, not Square's. The file on disk is pristine, and the binary
has no ASLR (fixed image base 0x400000), so file VAs == runtime VAs.

OUTPUT
------
  Phase A: every resolved chain address, with the three cross-checks.
  Phase B: per-state-handler disassembly summary -- every absolute-address
           global in 0x900000-0xE00000 that the handler touches, with
           mutation kind (inc/dec/add/sub/mov) and operand size, plus a
           ranked cursor-candidate list (small globals mutated by +-1
           style ops in command-phase handlers score highest).

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_battle_menu_static.py

No game required.
"""
import sys, os, struct, datetime
from collections import defaultdict

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed in this venv.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Tee logging (project rule: every investigation script logs itself).
# ---------------------------------------------------------------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_menu_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee

IMAGE_BASE = 0x400000

# Anchors: VAs embedded in FFNx's own symbol names (US 1.02 build, confirmed
# byte-identical in the 2026 rerelease for everything the mod touches).
BATTLE_MENU_UPDATE   = 0x6CE8B3   # ff7_externals.battle_menu_update_6CE8B3
BATTLE_SUB_6DB0EE    = 0x6DB0EE   # per-frame battle menu state dispatcher
EXPECT_TARGETING_FN  = 0x6E6291   # battle_update_targeting_info_6E6291
EXPECT_TARGETING_ID  = 0xDC3C98   # targeting_actor_id_DC3C98
EXPECT_DISPLAY_MENU  = 0x6D797C   # display_battle_menu_6D797C

# Data-region window for "interesting global" extraction. Covers menu-module
# BSS (0x9Axxxx), battle block (0xBExxxx-0xBFxxxx), savemap/menu (0xDBxxxx-
# 0xDCxxxx) and name-entry/title (0xDDxxxx) -- i.e. everywhere a cursor
# could plausibly live per the section-14 region map.
DATA_LO, DATA_HI = 0x900000, 0xE00000

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\Final Fantasy VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\Final Fantasy VII Steam Edition\ff7\resources\ff7_1.02\ff7_en",
]

# ---------------------------------------------------------------------------
# PE mapping helpers (same as ff7_wall_nav_static.py -- see that file for
# the section-table walk rationale).
# ---------------------------------------------------------------------------
def parse_pe_sections(data):
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    oph = struct.unpack_from('<H', data, pe + 20)[0]
    off = pe + 24 + oph
    out = []
    for i in range(nsec):
        s = off + i * 40
        va   = struct.unpack_from('<I', data, s + 12)[0]
        vsz  = struct.unpack_from('<I', data, s + 8)[0]
        roff = struct.unpack_from('<I', data, s + 20)[0]
        rsz  = struct.unpack_from('<I', data, s + 16)[0]
        out.append((va, max(vsz, rsz), roff))
    return out

_SECTIONS = None
def va_to_off(data, va):
    global _SECTIONS
    if _SECTIONS is None:
        _SECTIONS = parse_pe_sections(data)
    rva = va - IMAGE_BASE
    for va0, span, roff in _SECTIONS:
        if va0 <= rva < va0 + span:
            return roff + (rva - va0)
    return None

def read_bytes(data, va, n):
    off = va_to_off(data, va)
    if off is None or off + n > len(data):
        return None
    return data[off:off + n]

def read_u8(data, va):
    b = read_bytes(data, va, 1)
    return b[0] if b else None

def read_u32(data, va):
    b = read_bytes(data, va, 4)
    return struct.unpack('<I', b)[0] if b else None

def get_relative_call(data, base, offset):
    """FFNx get_relative_call: E8 rel32 at base+offset -> target.
    Verifies the opcode byte is really E8 so a misaligned offset fails
    loudly instead of yielding a garbage address."""
    op = read_u8(data, base + offset)
    if op != 0xE8:
        return None, (f"expected E8 at {base+offset:#x}, got "
                      f"{op:#04x}" if op is not None else "unmapped")
    rel = read_u32(data, base + offset + 1)
    if rel is None:
        return None, "rel32 unmapped"
    if rel >= 0x80000000:
        rel -= 0x100000000
    return (base + offset + 5 + rel) & 0xFFFFFFFF, None

def get_absolute_value(data, base, offset):
    v = read_u32(data, base + offset)
    return (v, None) if v is not None else (None, "unmapped")

def in_code(va):  return va is not None and 0x401000 <= va <= 0x9FFFFF
def in_data(va):  return va is not None and DATA_LO <= va < DATA_HI

# ---------------------------------------------------------------------------
# Function disassembly with the "extend past ret" heuristic: a handler may
# have early rets; keep going while any earlier forward jump targets code
# beyond the current position. Cap at 0x2000 bytes for safety.
# ---------------------------------------------------------------------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_function(data, entry, max_len=0x2000):
    raw = read_bytes(data, entry, max_len)
    if raw is None:
        return []
    insns = []
    max_target = entry          # furthest forward jump seen so far
    for insn in md.disasm(raw, entry):
        insns.append(insn)
        if insn.group(capstone.CS_GRP_JUMP):
            # record intra-function forward jump targets
            for op in insn.operands:
                if op.type == capstone.CS_OP_IMM and \
                   entry < op.imm < entry + max_len:
                    max_target = max(max_target, op.imm)
        if insn.mnemonic == 'ret' and insn.address >= max_target:
            break
        # int3 padding == fell off the end of the function
        if insn.mnemonic == 'int3':
            break
    return insns

# Mutation mnemonics that a cursor increment/decrement would use.
MUTATORS = {'inc', 'dec', 'add', 'sub', 'and', 'or', 'xor', 'mov'}

def extract_globals(insns):
    """Collect absolute-address data-region operands from an instruction
    list. Returns {addr: set of 'mnemonic/size/rw' descriptors}."""
    touched = defaultdict(set)
    for insn in insns:
        for op in insn.operands:
            if op.type != capstone.CS_OP_MEM:
                continue
            m = op.mem
            # absolute addressing only: no base register, no index register
            if m.base != 0 or m.index != 0:
                continue
            addr = m.disp & 0xFFFFFFFF
            if not in_data(addr):
                continue
            rw = 'w' if (op.access & capstone.CS_AC_WRITE) else 'r'
            touched[addr].add(f"{insn.mnemonic}/{op.size}B/{rw}")
    return touched

def is_plus_minus_one(insn):
    """True if this instruction adjusts its memory operand by exactly 1 --
    the signature of a cursor moving one row."""
    if insn.mnemonic in ('inc', 'dec'):
        return True
    if insn.mnemonic in ('add', 'sub') and len(insn.operands) == 2:
        src = insn.operands[1]
        if src.type == capstone.CS_OP_IMM and abs(src.imm) == 1:
            return True
    return False

# ---------------------------------------------------------------------------
def main():
    print(f"Log: {_log_path}")
    print("=" * 72)
    print("FF7 battle command-menu state machine -- static resolution")
    print("=" * 72)

    data = None
    for p in EXE_CANDIDATES:
        if os.path.exists(p):
            data = open(p, 'rb').read()
            print(f"Loaded exe: {p}  ({len(data):,} bytes)")
            break
    if data is None:
        print("ERROR: no ff7_en.exe found")
        return 1

    failures = []

    # ---------------- Phase A: chain resolution ------------------------
    print()
    print("--- Phase A: FFNx chain resolution -------------------------------")

    # Cross-check 1: anchor pair
    v, err = get_relative_call(data, BATTLE_MENU_UPDATE, 0xD9)
    print(f"grc(battle_menu_update+0xD9)      = "
          f"{v:#010x}" if v else f"FAILED: {err}")
    if v != BATTLE_SUB_6DB0EE:
        failures.append(f"anchor cross-check 1 failed: {v} != 0x6DB0EE")
    else:
        print("  MATCHES battle_sub_6DB0EE -- anchor pair validated")

    is_battle_paused, err = get_absolute_value(data, BATTLE_MENU_UPDATE, 0xC3)
    print(f"is_battle_paused                  = "
          f"{is_battle_paused:#010x}" if is_battle_paused else f"FAILED: {err}")

    battle_actor_data, err = get_absolute_value(data, BATTLE_SUB_6DB0EE, 0x276)
    print(f"battle_actor_data                 = "
          f"{battle_actor_data:#010x}" if battle_actor_data else f"FAILED: {err}")
    if battle_actor_data != 0xDC38E0:
        failures.append("battle_actor_data != known 0xDC38E0")
    else:
        print("  MATCHES known BATTLE_ACTOR_DATA 0xDC38E0 (v2.7 flash source)")

    fn_table_va, err = get_absolute_value(data, BATTLE_SUB_6DB0EE, 0x1B4)
    print(f"battle_menu_state_fn_table        = "
          f"{fn_table_va:#010x}" if fn_table_va else f"FAILED: {err}")

    # Cross-check 2+3: targeting chain
    tfn, err = get_relative_call(data, BATTLE_SUB_6DB0EE, 0x1F9)
    print(f"battle_update_targeting_info      = "
          f"{tfn:#010x}" if tfn else f"FAILED: {err}")
    if tfn != EXPECT_TARGETING_FN:
        failures.append(f"targeting fn {tfn} != 0x6E6291")
    else:
        print("  MATCHES battle_update_targeting_info_6E6291")
    if tfn:
        tid, err = get_absolute_value(data, tfn, 0x684)
        print(f"targeting_actor_id                = "
              f"{tid:#010x}" if tid else f"FAILED: {err}")
        if tid != EXPECT_TARGETING_ID:
            failures.append(f"targeting id {tid} != 0xDC3C98")
        else:
            print("  MATCHES targeting_actor_id_DC3C98 -- TARGET CURSOR FOUND")

    # display_battle_menu chain (for completeness / future hooks)
    s83C8, e1 = get_relative_call(data, BATTLE_MENU_UPDATE, 0x77)
    if s83C8:
        s82EA, e2 = get_relative_call(data, s83C8, 0xE0)
        if s82EA:
            dbm, e3 = get_relative_call(data, s82EA, 0x59)
            print(f"display_battle_menu               = "
                  f"{dbm:#010x}" if dbm else f"FAILED: {e3}")
            if dbm == EXPECT_DISPLAY_MENU:
                print("  MATCHES display_battle_menu_6D797C")

    if fn_table_va is None:
        print("FATAL: no fn table")
        return 1

    # Read the 64-entry state handler table.
    entries = []
    for i in range(64):
        e = read_u32(data, fn_table_va + i * 4)
        entries.append(e)

    handle_actor_ready = entries[0]
    print(f"handle_actor_ready (state 0)      = {handle_actor_ready:#010x}")
    bms, err = get_absolute_value(data, handle_actor_ready, 0x17B)
    print(f"battle_menu_state (WORD*)         = "
          f"{bms:#010x}" if bms else f"FAILED: {err}")
    if bms is not None and not in_data(bms):
        failures.append(f"battle_menu_state {bms:#x} outside data region")

    sbmsd, err = get_relative_call(data, handle_actor_ready, 0x187)
    print(f"set_battle_menu_state_data        = "
          f"{sbmsd:#010x}" if sbmsd else f"FAILED: {err}")

    dca, err = get_relative_call(data, BATTLE_SUB_6DB0EE, 0x50E)
    print(f"dispatch_chosen_battle_action     = "
          f"{dca:#010x}" if dca else f"FAILED: {err}")
    if dca:
        icid, _ = get_absolute_value(data, dca, 0x12B)
        iaid, _ = get_absolute_value(data, dca, 0x122)
        print(f"issued_command_id                 = {icid:#010x}")
        print(f"issued_action_id                  = {iaid:#010x}")

    if entries[19] and in_code(entries[19]):
        sbtd, err = get_relative_call(data, entries[19], 0x11A)
        print(f"set_battle_targeting_data         = "
              f"{sbtd:#010x}" if sbtd else f"FAILED: {err}")
        if sbtd:
            tt, _ = get_absolute_value(data, sbtd, 0x14E)
            ti, _ = get_absolute_value(data, sbtd, 0x164)
            print(f"issued_action_target_type         = {tt:#010x}")
            print(f"issued_action_target_index        = {ti:#010x}")

    print()
    print("State handler table (64 entries):")
    uniq = {}
    for i, e in enumerate(entries):
        tag = ""
        if e in uniq:
            tag = f"  (same as state {uniq[e]})"
        elif not in_code(e):
            tag = "  (NOT CODE -- null/sentinel)"
        else:
            uniq[e] = i
        print(f"  state {i:2d} -> {e:#010x}{tag}")

    # ---------------- Phase B: handler disassembly ---------------------
    print()
    print("--- Phase B: per-handler global extraction ------------------------")
    print("(absolute-address data operands in 0x900000-0xE00000; '+-1' marks")
    print(" inc/dec/add1/sub1 mutations -- the cursor-movement signature)")

    # Aggregates across handlers for the final ranking.
    global_handlers = defaultdict(set)   # addr -> set(state idx)
    global_ops      = defaultdict(set)   # addr -> descriptors
    plus_minus_one  = defaultdict(set)   # addr -> set(state idx) with +-1 ops

    for e, first_state in sorted(uniq.items(), key=lambda kv: kv[1]):
        if not in_code(e):
            continue
        insns = disasm_function(data, e)
        states = [i for i, x in enumerate(entries) if x == e]
        touched = extract_globals(insns)
        pm1 = set()
        for insn in insns:
            if is_plus_minus_one(insn):
                for op in insn.operands:
                    if (op.type == capstone.CS_OP_MEM and op.mem.base == 0
                            and op.mem.index == 0
                            and in_data(op.mem.disp & 0xFFFFFFFF)):
                        pm1.add(op.mem.disp & 0xFFFFFFFF)
        print()
        print(f"handler {e:#010x}  states={states}  "
              f"({len(insns)} insns, {len(touched)} globals)")
        for addr in sorted(touched):
            mark = "  <<< +-1 MUTATION" if addr in pm1 else ""
            print(f"    {addr:#010x}  {', '.join(sorted(touched[addr]))}{mark}")
        for addr, ops in touched.items():
            global_handlers[addr].update(states)
            global_ops[addr].update(ops)
        for addr in pm1:
            plus_minus_one[addr].update(states)

    # ---------------- Ranking ------------------------------------------
    print()
    print("--- Cursor candidate ranking --------------------------------------")
    print("Criteria: +-1 mutation anywhere (weight 4); mutated in a command-")
    print("phase handler, i.e. one serving a state < 19 (weight 2); written")
    print("with a 1- or 2-byte operand (weight 1); read by >1 handler (w 1).")
    scored = []
    for addr, states in global_handlers.items():
        score = 0
        why = []
        if addr in plus_minus_one:
            score += 4
            why.append(f"+-1 in states {sorted(plus_minus_one[addr])}")
        if any(s < 19 for s in (plus_minus_one.get(addr) or set())):
            score += 2
            why.append("command-phase mutation")
        if any(d.split('/')[1] in ('1B', '2B') and d.endswith('/w')
               for d in global_ops[addr]):
            score += 1
            why.append("small write")
        if len(states) > 1:
            score += 1
            why.append(f"shared by states {sorted(states)[:8]}")
        if score > 0:
            scored.append((score, addr, why))
    scored.sort(reverse=True)
    for score, addr, why in scored[:40]:
        print(f"  [{score}] {addr:#010x}  -- {'; '.join(why)}")

    print()
    print("=" * 72)
    if failures:
        print("RESULT: CROSS-CHECK FAILURES -- treat everything above as suspect:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("RESULT: OK -- all three anchor cross-checks passed.")
    print(f"battle_menu_state = {bms:#010x} (WORD; current widget/state)")
    print(f"Log saved to: {_log_path}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
