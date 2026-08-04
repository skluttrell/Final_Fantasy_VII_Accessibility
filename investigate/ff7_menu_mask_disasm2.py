#!/usr/bin/env python3
"""
ff7_menu_mask_disasm2.py -- follow-up to ff7_menu_mask_static.py
(2026-08-04): FULL unfiltered disassembly of the three code regions the
first pass identified, to reconstruct the exact mask formulas:

  A. 0x6CA380..0x6CA448 -- menu-open mask build: reads savemap +0xBC0/1
     (visible/enabled mask -- 0x02FB in the early save = all rows except
     Materia+PHS) and +0xBC2/3 (locking mask -- 0x0000 early) and +0xE13,
     stores SOMETHING into 0xDC1130.  Need: is 0xDC1130 = locking only,
     locking|~visible, and where does the visible mask copy go?
  B. 0x6CA4A8..0x6CA5A0 -- the activation/confirm path (known bit test
     0x6CA4CD reads 0xDC1130).  Need: does it ALSO test the visible
     mask, or is refusal purely 0xDC1130?
  C. 0x6CB600..0x6CB6E0 -- the other reader of +0xBC0/1 (0x6CB62D):
     almost certainly the row DRAW code deciding gray vs normal text.
     Need: which mask(s) drive the gray the sighted player sees.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"menu_mask_disasm2_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

import capstone

exe = next(c for c in (
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
) if os.path.isfile(c))
print(f"Reading: {exe}")
data = open(exe, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((va, vs, ro, rs))

def v2o(va):
    r = va - image_base
    for sva, svs, sro, srs in secs:
        if sva <= r < sva + max(svs, srs):
            return sro + (r - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

SAVEMAP_BASE = 0xDBFD38
NAMES = {
    0xDC1130: "DISABLED_ROWS", 0xDC1154: "MENU_CURSOR",
    0xDC1324: "FOCUS_MODE", 0xDC118C: "CHARSEL_CURSOR",
    0xDC1288: "CHARSEL_CHOSEN",
    0xDC08F8: "SM+BC0 vismask.lo", 0xDC08F9: "SM+BC1 vismask.hi",
    0xDC08FA: "SM+BC2 lockmask.lo", 0xDC08FB: "SM+BC3 lockmask.hi",
    0xDC0B4B: "SM+E13 (save-disable?)",
}
def ann(op_str):
    out = []
    for tok in op_str.replace('[', ' ').replace(']', ' ')\
            .replace(',', ' ').replace('+', ' ').split():
        if tok.startswith('0x'):
            try:
                a = int(tok, 16)
            except ValueError:
                continue
            if a in NAMES:
                out.append(NAMES[a])
            elif SAVEMAP_BASE <= a < SAVEMAP_BASE + 0x10F4:
                out.append(f"SM+0x{a - SAVEMAP_BASE:X}")
    return ("   ; " + ", ".join(out)) if out else ""

for title, start, end in (
    ("A. menu-open mask build", 0x6CA380, 0x6CA448),
    ("B. activation/confirm path", 0x6CA4A8, 0x6CA5A0),
    ("C. row draw (reader of vismask at 0x6CB62D)", 0x6CB5C0, 0x6CB700),
):
    print(f"===== {title}: 0x{start:X}..0x{end:X} =====")
    o = v2o(start)
    # find a decode alignment that produces a clean run through the region
    best = None
    for adj in range(16):
        insns = list(md.disasm(data[o + adj:o + (end - start)], start + adj))
        cov = insns[-1].address + insns[-1].size - (start + adj) if insns else 0
        if best is None or cov > best[0]:
            best = (cov, adj, insns)
        if cov >= (end - start - adj - 4):
            break
    for ins in best[2]:
        print(f"  0x{ins.address:08X}  {ins.mnemonic} {ins.op_str}"
              f"{ann(ins.op_str)}")
    print()

print("Done.")
