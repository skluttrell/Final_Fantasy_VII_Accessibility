#!/usr/bin/env python3
"""
ff7_title_loop_disasm.py -- Disassemble the title module's main loop to
find the phase variable that guards the menu draw call (follow-up to
ff7_title_phase_static.py, 2026-07-27).

WHY: the title-menu draw function 0x72141F (reads TITLE_CURSOR 0xDD6F24
for the finger position) is called from 0x713703, and its sibling
0x721479 from 0x71375D — so 0x7136xx-0x7137xx is the title module's
per-frame dispatch. The conditional structure around those call sites
reads whatever state says "logos / intro movie / menu displayed" — the
signal TitleCursorThread needs to stop announcing "New Game" during the
launch splash.

METHOD: plain window disasm of 0x713300-0x713A00 (plus a second window
covering whatever cmp targets appear), labeling every static referenced
and marking the two known call sites. Eyeball output; the phase variable
then gets a live launch-to-title capture before shipping.
"""
import sys, os, struct, datetime

import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"title_loop_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    sections.append((va, vs, rp))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

KNOWN = {
    0xDD6F24: "TITLE_CURSOR(widget0xDD6F20+4)",
    0xDD6F20: "TITLE_WIDGET",
    0xDD6D98: "LOADMENU_GRID_CURSOR(widget)",
    0xDD74E0: "title_74E0(cmp2/draw-skip)",
    0xDD7704: "title_7704(cmp7/draw-skip)",
    0xDD7738: "title_7738(handler-retval)",
    0xDD76FC: "title_76FC(saves-exist?)",
    0xDD7608: "title_7608",
    0xDD7610: "title_7610",
    0xCC15D0: "FIELD_ID",
    0xCC0D89: "GAME_MODE",
    0xCC1638: "MOVIE_PLAYING",
    0xDC0FE9: "MENU_OPEN",
    0xDC0E70: "title_DC0E70",
}
MARK_SITES = {0x713703, 0x71375D}

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def dump(lo, hi, title):
    print(f"===== {title}: 0x{lo:X}..0x{hi:X} =====")
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
        site = "  <<<< KNOWN CALL SITE" if insn.address in MARK_SITES else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}{site}")
    print()

# The title dispatch region around the two known call sites, wide.
dump(0x713300, 0x713A00, "title module dispatch (callers of the draw subs)")
# The input/confirm handler's own function head (the switch preamble that
# the phase-hunt log entered mid-function at 0x7221xx).
dump(0x721F00, 0x722330, "title input/confirm handler (head + body)")
