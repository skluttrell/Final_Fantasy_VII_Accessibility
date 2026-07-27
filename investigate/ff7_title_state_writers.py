#!/usr/bin/env python3
"""
ff7_title_state_writers.py -- Close the last static question on the
title-state hunt (2026-07-27): is the title module's init-once guard
0xDD76F8 cleared on exit, so 0xDD74E0 (the fade/lifecycle state, ==1 =
title menu interactive) re-cycles 0->1 on EVERY title entry (boot,
post-game-over, quit-to-title)?

METHOD: full .text sweep for every instruction referencing 0xDD76F8,
plus a disasm of the title main's tail (0x7223F9..0x7224D0 — the
[0xDD74E0]==-1 teardown branch the previous window cut off).
"""
import sys, os, struct, datetime

import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"title_state_writers_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    chars = struct.unpack_from('<I', data, off + 36)[0]
    sections.append((va, vs, rp, rs, chars))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp, srs, _ in sections:
        if sva <= rva < sva + svs:
            d = rva - sva
            return srp + d if d < srs else None
    return None

TARGET = 0xDD76F8
KNOWN = {
    0xDD76F8: "title_init_guard",
    0xDD74E0: "title_74E0(fade/lifecycle)",
    0xDD7704: "title_7704(subscreen)",
    0xDD7738: "title_7738(retval)",
    0xDC1210: "menu_tick_0xDC1210",
    0xDC12E4: "0xDC12E4",
}

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

CODE_CHAR = 0x20000000
CHUNK = 0x10000
hits = []
for sva, svs, srp, srs, chars in sections:
    if not (chars & CODE_CHAR):
        continue
    size = min(svs, srs)
    base_va = image_base + sva
    pos = 0
    while pos < size:
        chunk = data[srp + pos: srp + min(pos + CHUNK + 16, size)]
        for insn in md.disasm(chunk, base_va + pos):
            if insn.id == 0:
                continue
            if insn.address >= base_va + pos + CHUNK:
                break
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and \
                        (op.mem.disp & 0xFFFFFFFF) == TARGET:
                    acc = "WRITE" if op.access & capstone.CS_AC_WRITE else "read"
                    hits.append((insn.address, acc,
                                 f"{insn.mnemonic} {insn.op_str}"))
        pos += CHUNK

print(f"0xDD76F8 references ({len(hits)}):")
for va, acc, text in hits:
    print(f"  0x{va:X}: [{acc}] {text}")

print("\n===== title main tail (teardown branch): 0x7223F9..0x7224D8 =====")
off = va_to_off(0x7223F9)
for insn in md.disasm(data[off:off + (0x7224D8 - 0x7223F9)], 0x7223F9):
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
