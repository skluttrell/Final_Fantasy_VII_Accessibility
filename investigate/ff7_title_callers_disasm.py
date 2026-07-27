#!/usr/bin/env python3
"""
ff7_title_callers_disasm.py -- Find the REAL callers of the title-menu
draw/input functions and every writer of the title-block state statics
(third pass of the launch-splash hunt, 2026-07-27).

WHY: pass 2's raw-E8 caller scan produced false positives — the "call
sites" at 0x713703/0x71375D were E8 bytes INSIDE `cmp [0xDD17E8],...`
operands (lesson: raw byte scans for E8 need disasm confirmation). The
title draw subs (0x72141F hi-res, 0x721479 lo-res — both read
TITLE_CURSOR 0xDD6F24 = widget 0xDD6F20 +4 row) and the input handler
(0x72226C region, OK-switch on the cursor) are dispatched by SOMETHING
that knows the menu is on screen — that dispatcher's state variable is
the fix for the launch-splash false "New Game".

METHOD: one full disassembly sweep of .text (chunked with skipdata AND
restarts — the truncation lesson), collecting
  (a) every `call imm32` whose target is one of the known title subs;
  (b) every instruction referencing the title state statics
      (0xDD74E0 / 0xDD7704 / 0xDD7738 / 0xDD76FC / 0xDD7608 / 0xDD7610 /
       widget 0xDD6F20) with read/write access noted;
then windows around (a) sites and around every WRITE in (b) — init
writes reveal the title module's entry, and the draw dispatch reveals
the phase test.
"""
import sys, os, struct, datetime
from collections import defaultdict

import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"title_callers_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

with open(find_exe_path(), 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff_off = e_lfanew + 4
num_sections = struct.unpack_from('<HH', data, coff_off)[1]
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + 20 + opt_hdr_size - 20
sections = []
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

DRAW_SUBS = {0x72141F: "title_draw_hires", 0x721479: "title_draw_lores"}
STATE = {
    0xDD74E0: "title_74E0",
    0xDD7704: "title_7704",
    0xDD7738: "title_7738",
    0xDD76FC: "title_76FC",
    0xDD7608: "title_7608",
    0xDD7610: "title_7610",
    0xDD6F20: "TITLE_WIDGET",
    0xDD6F24: "TITLE_CURSOR",
}
KNOWN = dict(STATE)
KNOWN.update({0xCC15D0: "FIELD_ID", 0xCC0D89: "GAME_MODE",
              0xCC1638: "MOVIE_PLAYING", 0xDC0FE9: "MENU_OPEN"})

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

CODE_CHAR = 0x20000000
CHUNK = 0x10000
call_hits = []       # (site_va, target)
state_hits = []      # (insn_va, static, access, text)
for name, sva, svs, srp, srs, chars in sections:
    if not (chars & CODE_CHAR):
        continue
    size = min(svs, srs)
    base_va = image_base + sva
    print(f"sweeping {name}: 0x{base_va:08X}..0x{base_va+size:08X}")
    pos = 0
    while pos < size:
        chunk = data[srp + pos: srp + min(pos + CHUNK + 16, size)]
        for insn in md.disasm(chunk, base_va + pos):
            if insn.id == 0:
                continue
            if insn.address >= base_va + pos + CHUNK:
                break
            if insn.mnemonic == 'call':
                try:
                    tgt = int(insn.op_str, 16)
                except ValueError:
                    tgt = None
                if tgt in DRAW_SUBS:
                    call_hits.append((insn.address, tgt))
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    d = op.mem.disp & 0xFFFFFFFF
                    if d in STATE:
                        acc = "WRITE" if op.access & capstone.CS_AC_WRITE else "read"
                        state_hits.append((insn.address, d, acc,
                                           f"{insn.mnemonic} {insn.op_str}"))
        pos += CHUNK

print(f"\ncalls to draw subs ({len(call_hits)}):")
for va, tgt in call_hits:
    print(f"  0x{va:X} -> {DRAW_SUBS[tgt]} (0x{tgt:X})")

print(f"\ntitle-state references ({len(state_hits)}):")
for va, d, acc, text in sorted(state_hits):
    print(f"  0x{va:X}: [{acc:5s}] {STATE[d]:14s} {text}")

def dump(lo, hi, title):
    print(f"\n===== {title}: 0x{lo:X}..0x{hi:X} =====")
    off = va_to_off(lo)
    if off is None:
        print("  (unmapped)")
        return
    for insn in md.disasm(data[off:off + (hi - lo)], lo):
        if insn.id == 0:
            continue
        marks = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
                if 0x900000 <= d <= 0xE00000:
                    marks.append(KNOWN.get(d, f"0x{d:X}"))
        star = ("   <== " + ",".join(marks)) if marks else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}")

# Windows around the real call sites.
printed = set()
for va, tgt in call_hits:
    key = (va - 0x120) & ~0x3F
    if key in printed:
        continue
    printed.add(key)
    dump(va - 0x120, va + 0x80, f"around call@0x{va:X} -> {DRAW_SUBS[tgt]}")

# Windows around every WRITE to a state static (init/entry evidence).
for va, d, acc, text in sorted(state_hits):
    if acc != "WRITE":
        continue
    key = (va - 0x80) & ~0x3F
    if key in printed:
        continue
    printed.add(key)
    dump(va - 0x80, va + 0x80, f"around WRITE@0x{va:X} ({STATE[d]}: {text})")
