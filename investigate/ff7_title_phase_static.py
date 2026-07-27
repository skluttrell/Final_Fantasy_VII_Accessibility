#!/usr/bin/env python3
"""
ff7_title_phase_static.py -- Hunt the "title menu is actually on screen"
signal (the launch-splash false "New Game" announce, 2026-07-27).

WHY: TitleCursorThread's known limitation — at process start the title
cursor byte TITLE_CURSOR (0xDD6F24) is BSS-zero and FIELD_ID is 0, so the
mod announces "New Game" ~350ms into the company-logo splash, long before
the title menu exists; when the real menu appears (same cursor value 0)
the change-check then suppresses the announce the player actually needed.
Confirmed again in the 2026-07-27 09:57:06 log (announce fired before
address resolution even completed). The fix needs a positive "title menu
is displayed" signal; none is currently mapped.

METHOD (static-first playbook): the code that WRITES 0xDD6F24 runs only
while the title menu is live (it is the Up/Down handler), and its guards
must read whatever phase/visibility state the title module keeps:
  1. sweep EVERY executable byte for instructions whose memory operand
     displacement equals 0xDD6F24 (array-form [reg*N+disp] included --
     the §6 lesson: a plain-[imm32] filter finds zero array refs);
  2. print a disasm window around every hit;
  3. within those windows, tally every OTHER static address referenced,
     grouped by BSS neighborhood -- cmp/test sites against small
     immediates are phase-variable candidates;
  4. also locate the CALLERS of the containing code (rel32 call targets
     that land near the hits) for one level of context, since the title
     module's state machine likely dispatches the menu handler from a
     phase switch.
Whatever candidate emerges gets a live launch-to-title capture before
anything ships (a scan finds A correlated cell, not THE source — §6).

Capstone note: linear disasm STOPS at the first undecodable byte unless
restarted past it (talk-range hunt lesson) — this sweep uses skipdata
AND per-chunk restarts so coverage is real.
"""
import sys, os, struct, datetime
from collections import defaultdict

import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"title_phase_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore)
print(f"Output saving to: {_log_path}\n")

def find_exe_path():
    for cand in (
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    ):
        if os.path.isfile(cand):
            return cand
    raise RuntimeError("ff7_en.exe not found")

exe = find_exe_path()
print(f"exe: {exe}")
with open(exe, 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff_off = e_lfanew + 4
num_sections = struct.unpack_from('<HH', data, coff_off)[1]
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + 20 + opt_hdr_size - 20
sections = []      # (name, va, vsize, rawptr, rawsize, characteristics)
for i in range(num_sections):
    off = section_off + i * 40
    name = data[off:off + 8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    chars = struct.unpack_from('<I', data, off + 36)[0]
    sections.append((name, va, vs, rp, rs, chars))

def va_to_off(va):
    rva = va - image_base
    for _, sva, svs, srp, srs, _ in sections:
        if sva <= rva < sva + svs:
            d = rva - sva
            return srp + d if d < srs else None
    return None

TITLE_CURSOR = 0xDD6F24
# The known title-block neighbors (continue_menu_scan 2026-07-17) — used to
# label tallied addresses that are already mapped.
KNOWN = {
    0xDD6F24: "TITLE_CURSOR",
    0xDD6D98: "LOADMENU_GRID_CURSOR",
    0xDD6D9C: "LOADMENU_GRID_ROW",     # +4 struct spacing (research §4)
    0xCC15D0: "FIELD_ID",
    0xCC0D89: "GAME_MODE",
    0xCC1638: "FIELD_MOVIE_PLAYING",
    0xDC0FE9: "MENU_OPEN",
}

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

# ---- pass 1: full executable sweep for 0xDD6F24 references ----------------
CODE_CHAR = 0x20000000  # IMAGE_SCN_MEM_EXECUTE
hits = []               # (insn_va, access, mnemonic+ops)
CHUNK = 0x10000
for name, sva, svs, srp, srs, chars in sections:
    if not (chars & CODE_CHAR):
        continue
    size = min(svs, srs)
    base_va = image_base + sva
    print(f"sweeping section {name}: VA 0x{base_va:08X}..0x{base_va+size:08X}")
    pos = 0
    while pos < size:
        # Per-chunk restart with 16-byte overlap so an instruction spanning
        # the boundary is not lost; skipdata carries us over junk inside.
        chunk = data[srp + pos: srp + min(pos + CHUNK + 16, size)]
        for insn in md.disasm(chunk, base_va + pos):
            if insn.id == 0:
                continue
            if insn.address >= base_va + pos + CHUNK:
                break
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and \
                        (op.mem.disp & 0xFFFFFFFF) == TITLE_CURSOR:
                    acc = "WRITE" if op.access & capstone.CS_AC_WRITE else "read"
                    hits.append((insn.address, acc,
                                 f"{insn.mnemonic} {insn.op_str}"))
        pos += CHUNK

print(f"\n{len(hits)} instruction(s) reference 0x{TITLE_CURSOR:X}:")
for va, acc, text in hits:
    print(f"  0x{va:X}: [{acc}] {text}")

# ---- pass 2: disasm windows + neighbor tally ------------------------------
tally = defaultdict(set)     # static disp -> set of referencing insn VAs
printed = set()
for va, acc, text in hits:
    wstart = va - 0x100
    key = wstart & ~0x3F
    print(f"\n--- window around 0x{va:X} ({acc}: {text}) ---")
    if key in printed:
        print("    (overlaps a window printed above)")
        continue
    printed.add(key)
    woff = va_to_off(wstart)
    if woff is None:
        continue
    for insn in md.disasm(data[woff:woff + 0x200], wstart):
        if insn.id == 0:
            continue
        marks = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
                # Statics only: FF7's globals live above the image base and
                # below 0xE00000; small disps are struct offsets, not addrs.
                if 0x900000 <= d <= 0xE00000:
                    tally[d].add(insn.address)
                    marks.append(KNOWN.get(d, f"0x{d:X}"))
        star = ("   <== " + ",".join(marks)) if marks else ""
        cur = " <<<<" if insn.address == va else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}{cur}")

# ---- pass 3: callers of the hit neighborhoods (one level) -----------------
# rel32 E8 calls landing within 0x40 bytes before any hit — names the title
# state machine that dispatches the cursor handler.
hit_vas = sorted({va for va, _, _ in hits})
call_targets = set()
for va in hit_vas:
    call_targets.add(va)
print("\ncallers whose call target lands near a hit (scan of E8 rel32):")
for name, sva, svs, srp, srs, chars in sections:
    if not (chars & CODE_CHAR):
        continue
    size = min(svs, srs)
    base_va = image_base + sva
    raw = data[srp:srp + size]
    i = 0
    while True:
        i = raw.find(b'\xE8', i)
        if i < 0:
            break
        if i + 5 <= size:
            rel = struct.unpack_from('<i', raw, i + 1)[0]
            tgt = base_va + i + 5 + rel
            for hva in hit_vas:
                if 0 <= hva - tgt <= 0x400:
                    print(f"  call @0x{base_va+i:X} -> 0x{tgt:X} "
                          f"(hit 0x{hva:X} is +0x{hva-tgt:X} into it)")
                    break
        i += 1

# ---- summary --------------------------------------------------------------
print("\nstatic addresses referenced inside the hit windows (candidates for")
print("the title phase/visible state; KNOWN names labeled):")
for d in sorted(tally):
    label = KNOWN.get(d, "")
    print(f"  0x{d:X}  refs={len(tally[d]):2d}  {label}")
print("\nNext: eyeball the windows — the cursor writer's guarding cmp/test")
print("against a small immediate names the phase variable; verify live at")
print("the next launch (log it through splash->title) before shipping.")
