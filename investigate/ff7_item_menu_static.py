#!/usr/bin/env python3
"""
ff7_item_menu_static.py -- Statically locate the ITEM menu's cursor globals
(2026-07-18; user request: make the Item menu speak).

WHAT THE ITEM MENU NEEDS SPOKEN (from Screenshots/Menus/items_menu_1/2.png):
  - top bar cursor: Use / Arrange / Key Items
  - item list cursor: which inventory row ("Potion, 4") + scroll (list
    windows ~10 visible rows over up to 320 slots)
  - target pane cursor: which party member an item is about to be used on
  - key-items list cursor
  - (data itself needs NO scanning: inventory = savemap items[320] at
    0xDC0234 = savemap+0x4FC, word = id | qty<<9; key items = 32-byte
    bitmask at 0xDC0894 = savemap+0xB5C; both straight from FFNx's savemap
    struct, anchored by the live-verified SAVEMAP_PARTY_IDS at +0x4F8.)

METHOD (exe on disk, zero live interaction — the approach that cracked the
battle menu after live-only scans failed 3 sessions):
  1. FFNx name-embedded anchor: menu_sub_6CB56A = 0x6CB56A dispatches the
     main menu's sub-screens through menu_subs_call_table, whose address is
     the dword operand at +0x2EC (FFNx ff7_data.h line 297,
     get_absolute_value = raw dword read at base+offset).
  2. Read the table (16 dword slots, filter to plausible code VAs). Known
     indices from FFNx cross-check the read: [5]=status 0x-something,
     [8]=config, [10]=save 0x6FEDB0 (name-embedded — must match exactly).
  3. Identify the ITEM menu entry: the only sub-screen whose code (entry +
     one level of intra-module calls) references BOTH the savemap items
     array region AND the key-items bitmask region. (The Key Items tab
     lives inside the Item menu — see items_menu_1.png top bar.)
  4. Mine that code for cursor candidates: absolute BSS addresses in
     0xDC0000-0xDCFFFF that the code WRITES (cursor movement) — the same
     write-side mining that found the save menu's DC6Axx block. Report
     each with reference count, read/write split, and nearby known symbols
     (MENU_CURSOR 0xDC1154 etc.) for orientation.

Output feeds a live speak-back probe (ff7_item_menu_probe.py) before
anything ships — static candidates rank, live behavior decides.
"""
import sys, os, struct, datetime, subprocess
from collections import defaultdict

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed. Run: venv/Scripts/python.exe -m pip install capstone")
    sys.exit(1)

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"item_menu_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
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

# -- locate the exe on disk ------------------------------------------------------
def find_exe_path():
    try:
        out = subprocess.check_output(
            ['wmic', 'process', 'where', "name='ff7_en.exe'", 'get', 'ExecutablePath'],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.lower().endswith('.exe'):
                return line
    except Exception:
        pass
    for cand in (
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    ):
        if os.path.isfile(cand):
            return cand
    raise RuntimeError("Could not locate ff7_en.exe")

exe_path = find_exe_path()
print(f"Reading exe: {exe_path}")
with open(exe_path, 'rb') as f:
    data = f.read()
print(f"  {len(data):,} bytes\n")

# -- minimal PE parse ------------------------------------------------------------
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\0\0'
coff_off = e_lfanew + 4
num_sections = struct.unpack_from('<HH', data, coff_off)[1]
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + opt_hdr_size
sections = []
for i in range(num_sections):
    off = section_off + i * 40
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    sections.append((va, vs, rp))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

def gav(addr, offset):
    """FFNx get_absolute_value: raw dword at base+offset."""
    off = va_to_off(addr + offset)
    return struct.unpack_from('<I', data, off)[0] if off is not None else None

# -- known landmarks -------------------------------------------------------------
MENU_DISPATCH   = 0x6CB56A          # FFNx menu_sub_6CB56A (name-embedded VA)
TABLE_OPERAND   = 0x2EC             # ff7_data.h: menu_subs_call_table operand
SAVE_MENU_SUB   = 0x6FEDB0          # FFNx menu_sub_6FEDB0 = table[10] (save/load)
ITEMS_LO, ITEMS_HI       = 0xDC0234, 0xDC0234 + 320*2      # savemap items[320]
KEYBITS_LO, KEYBITS_HI   = 0xDC0894, 0xDC0894 + 32         # key-item bitmask
BSS_LO, BSS_HI           = 0xDC0000, 0xDD0000              # cursor hunt range
CODE_LO, CODE_HI         = 0x401000, 0x800000
MENU_MOD_LO, MENU_MOD_HI = 0x6C0000, 0x720000              # menu module code

KNOWN = {
    0xDC1154: "MENU_CURSOR", 0xDC12DC: "MENU_OPEN", 0xDC10F0: "CONFIG_ROW",
    0xDC6AE4: "SAVEMENU_GRID_ROW", 0xDC6B2C: "SAVEMENU_SLOT_SCROLL",
    0xDC6C6C: "SAVEMENU_CONFIRM_CURSOR", 0xDCA028: "SAVEMENU_WIDGET_STATE",
}

# -- locate the top-bar caption strings ------------------------------------------
# FF7 PC text encoding is ASCII-0x20 for the printable range (ff7_text.cpp:
# "byte + 0x20 is exact"), terminator 0xFF. "Arrange" and "Key Items" are
# captions unique to the Item menu's top bar (items_menu_1.png) — whichever
# sub-screen's code references their addresses IS the item menu, independent
# of the items-array evidence.
def off_to_va(off):
    for sva, svs, srp in sections:
        if srp <= off < srp + svs:
            return image_base + sva + (off - srp)
    return None

def ff7_encode(s):
    return bytes((ord(c) - 0x20) & 0xFF for c in s) + b'\xff'

STR_VAS = {}          # va -> label
for label in ("Arrange", "Key Items"):
    pat = ff7_encode(label)
    start = 0
    hits = []
    while True:
        idx = data.find(pat, start)
        if idx < 0:
            break
        va = off_to_va(idx)
        if va is not None:
            hits.append(va)
            STR_VAS[va] = label
        start = idx + 1
    print(f'FF7-encoded "{label}": ' +
          (", ".join(f"0x{v:X}" for v in hits) if hits else "NOT FOUND"))
print()

table_va = gav(MENU_DISPATCH, TABLE_OPERAND)
print(f"menu_subs_call_table operand @ 0x{MENU_DISPATCH:X}+0x{TABLE_OPERAND:X} -> 0x{table_va:X}")
toff = va_to_off(table_va)
assert toff is not None, "table VA not mapped — chain broke, do not trust anything"

entries = []
for i in range(16):
    v = struct.unpack_from('<I', data, toff + i*4)[0]
    entries.append(v)
    ok = CODE_LO <= v < CODE_HI
    print(f"  table[{i:2}] = 0x{v:08X} {'(code)' if ok else '(NOT CODE - end/garbage?)'}")

# Cross-check: FFNx says table[10] is the save menu, and that sub's FFNx
# name embeds its address. If this fails the operand read was wrong.
assert entries[10] == SAVE_MENU_SUB, (
    f"table[10]=0x{entries[10]:X} != menu_sub_6FEDB0 — WRONG TABLE, stop")
print(f"\nCROSS-CHECK PASS: table[10] == 0x{SAVE_MENU_SUB:X} (FFNx menu_sub_6FEDB0, save menu)\n")

# -- disassembly mining ----------------------------------------------------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

FUNC_WINDOW = 0x1800    # linear sweep length per function (mining, not proof)
MAX_FUNCS   = 400       # per-entry BFS cap (menu subs are deep state machines)
MAX_DEPTH   = 4         # call-follow depth; the first sweep at depth 1 found
                        # ZERO items-array refs anywhere — the inventory code
                        # is buried in helpers, so recurse (cached, so cheap)

# Per-function cache: fva -> (reads, writes, callees). Menu helpers are
# heavily shared between sub-screens; computing each once makes the deep
# sweep affordable and keeps every entry's BFS consistent.
_func_cache = {}

def sweep_func(fva):
    if fva in _func_cache:
        return _func_cache[fva]
    reads, writes, callees = defaultdict(list), defaultdict(list), []
    str_hits = []
    foff = va_to_off(fva)
    if foff is not None:
        code = data[foff:foff + FUNC_WINDOW]
        for insn in md.disasm(code, fva):
            if insn.id == 0:      # skipdata filler
                continue
            if insn.mnemonic == 'call':
                try:
                    tgt = int(insn.op_str, 16)
                    if MENU_MOD_LO <= tgt < MENU_MOD_HI:
                        callees.append(tgt)
                except ValueError:
                    pass
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM and \
                        (op.imm & 0xFFFFFFFF) in STR_VAS:
                    str_hits.append((insn.address,
                                     STR_VAS[op.imm & 0xFFFFFFFF]))
                if op.type == capstone.x86.X86_OP_MEM:
                    tgt = op.mem.disp & 0xFFFFFFFF
                    if not (0xDB0000 <= tgt < 0xDE0000):
                        continue
                    # Indexed forms ([ecx*2 + disp]) are ARRAY accesses —
                    # exactly how items[320] compiles. Keep them for the
                    # discriminator but tag them, because a cursor scalar
                    # must be a plain [imm32] access. (The first two runs
                    # filtered indexed forms out entirely and found ZERO
                    # items refs — that filter was the bug, not the theory.)
                    plain = (op.mem.base == 0 and op.mem.index == 0)
                    rec = (insn.address,
                           f"{insn.mnemonic} {insn.op_str}" +
                           ("" if plain else "  [indexed]"))
                    if op.access & capstone.CS_AC_WRITE:
                        writes[tgt].append(rec)
                    if op.access & capstone.CS_AC_READ:
                        reads[tgt].append(rec)
    result = (reads, writes, callees, str_hits)
    _func_cache[fva] = result
    return result

def sweep(entry_va, depth):
    """BFS entry + intra-menu-module calls to `depth` levels.
    Returns (reads, writes, str_hits)."""
    reads, writes = defaultdict(list), defaultdict(list)
    str_hits = []
    seen = set()
    frontier = [entry_va]
    for _ in range(depth):
        nxt = []
        for fva in frontier:
            if fva in seen or len(seen) >= MAX_FUNCS:
                continue
            seen.add(fva)
            r, w, callees, sh = sweep_func(fva)
            for va, recs in r.items():
                reads[va].extend(recs)
            for va, recs in w.items():
                writes[va].extend(recs)
            str_hits.extend(sh)
            nxt.extend(callees)
        frontier = nxt
    return reads, writes, str_hits

def hits_in(refs, lo, hi):
    return sum(len(v) for k, v in refs.items() if lo <= k < hi)

print("=" * 70)
print("PHASE 1: which table entry is the ITEM menu?")
print("  Primary evidence: refs to the FF7-encoded 'Arrange'/'Key Items'")
print("  caption strings (unique to the Item menu top bar). Secondary:")
print("  refs into savemap items[320]/key-item bitmask. Scored SHALLOW")
print("  (depth 2) — the depth-4 sweep reached shared helpers and scored")
print("  every sub-screen equally, which is how the first run misled.")
print("=" * 70)
results = {}
for i, ev in enumerate(entries):
    if not (CODE_LO <= ev < CODE_HI):
        continue
    if any(r[0] == ev for r in results.values()):
        continue                     # duplicate table slot, already swept
    reads, writes, str_hits = sweep(ev, 2)
    item_refs = hits_in(reads, ITEMS_LO, ITEMS_HI) + hits_in(writes, ITEMS_LO, ITEMS_HI)
    key_refs  = hits_in(reads, KEYBITS_LO, KEYBITS_HI) + hits_in(writes, KEYBITS_LO, KEYBITS_HI)
    results[i] = (ev, item_refs, key_refs, str_hits)
    strs = ", ".join(sorted({lbl for _, lbl in str_hits})) or "-"
    print(f"  table[{i:2}] 0x{ev:08X}: caption refs=[{strs}]  "
          f"items refs={item_refs:3}  keyitem refs={key_refs:3}")

best = max(results, key=lambda i: (len(results[i][3]),
                                   results[i][1] + results[i][2]))
ev, ir, kr, sh = results[best]
print(f"\n==> ITEM MENU CANDIDATE: table[{best}] = 0x{ev:08X} "
      f"(caption refs={len(sh)}, items refs={ir}, keyitem refs={kr})")
if not sh:
    print("    WARNING: no caption-string refs — identification NOT trustworthy.")

# Deep sweep of the winner only, for cursor mining.
reads, writes, _ = sweep(ev, MAX_DEPTH)

print()
print("=" * 70)
print(f"PHASE 2: BSS globals WRITTEN by table[{best}] (cursor candidates)")
print("  sorted by address; W=writes R=reads; known symbols marked")
print("=" * 70)
all_vas = sorted(set(list(reads.keys()) + list(writes.keys())))
for va in all_vas:
    if not (BSS_LO <= va < BSS_HI):
        continue
    w, r = writes.get(va, []), reads.get(va, [])
    if not w:
        continue                      # cursors get WRITTEN by input handling
    if all("[indexed]" in txt for _, txt in w):
        continue                      # array base, not a scalar cursor
    tag = KNOWN.get(va, "")
    near = ""
    if not tag:
        for kva, kname in KNOWN.items():
            if abs(va - kva) <= 0x40:
                near = f"(near {kname}{va-kva:+#x})"
                break
    print(f"  0x{va:08X}  W={len(w):3} R={len(r):3}  {tag}{near}")
    # first two write contexts, for eyeballing inc/dec vs table writes
    for iva, txt in w[:2]:
        print(f"        @0x{iva:X}: {txt}")

print()
print("=" * 70)
print("PHASE 3: same, for OTHER plausible sub-screens (context — shared")
print("  cursor helpers show up as globals written by several subs)")
print("=" * 70)
shared = defaultdict(list)
for i, (ev2, _, _, _) in results.items():
    _, w2, _ = sweep(ev2, 2)         # cached, cheap
    for va in w2:
        if BSS_LO <= va < BSS_HI:
            shared[va].append(i)
multi = {va: subs for va, subs in shared.items() if len(subs) > 1}
for va in sorted(multi):
    tag = KNOWN.get(va, "")
    print(f"  0x{va:08X} written by subs {multi[va]}  {tag}")

print()
print("=" * 70)
print(f"PHASE 4: globals written by table[{best}]'s OWN code (depth 2) and")
print("  by NO other sub-screen — the item menu's exclusive state. This is")
print("  the primary cursor candidate list (phase 2's deep sweep drags in")
print("  shared window/helper state; exclusivity cuts that noise).")
print("=" * 70)
_, w_best, _ = sweep(ev, 2)
others = set()
for i, (ev2, _, _, _) in results.items():
    if i == best:
        continue
    _, w2, _ = sweep(ev2, 2)
    others.update(w2.keys())
for va in sorted(w_best):
    if not (BSS_LO <= va < BSS_HI) or va in others:
        continue
    w = w_best[va]
    if all("[indexed]" in txt for _, txt in w):
        continue
    tag = KNOWN.get(va, "")
    print(f"  0x{va:08X}  W={len(w):3}  {tag}")
    for iva, txt in w[:3]:
        print(f"        @0x{iva:X}: {txt}")

print("\nDone. Feed the Phase-4 list to ff7_item_menu_probe.py for live speak-back.")
