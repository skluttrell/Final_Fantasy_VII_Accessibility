#!/usr/bin/env python3
"""
ff7_idlck_bitmath.py -- Phase 3 of the triangle-lock investigation: find the
lock CONSUMER by its bit-math signature (2026-07-23).

Phase 2 (idlck_readers log) showed the exact [reg+reg+0xB2] access form is
unique to the IDLCK handler -- the consumer computes the address some other
way. But ANY reader of a bitfield indexed by triangle id must do the same
arithmetic the handler does:

    byte_index = id >> 3        (sar/shr reg, 3)
    bit        = id & 7         (and reg, 7)
    mask       = 1 << bit       (shl) or a mask-table lookup

This script scans the FIELD MODULE code range (0x600000-0x6FFFFF, per the
region map) for every `sar`/`shr` by 3, then checks a ±20-instruction window
for an `and ..., 7` AND a byte-size memory access -- the triple only occurs
together in bitfield code. Each candidate site is dumped with generous
context so the surrounding function is identifiable. The IDLCK handler
itself (0x61E29F..0x61E3C5) will appear and validates the detector.

Requires capstone (already in investigate/venv).
"""
import sys, os, struct, datetime

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed.")
    sys.exit(1)

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"idlck_bitmath_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def find_exe_path():
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

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
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
    flags = struct.unpack_from('<I', data, off + 36)[0]
    sections.append((va, vs, rp, rs, flags))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp, srs, _ in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# Field module range per the §14 region map; extend a little each way.
SCAN_LO, SCAN_HI = 0x600000, 0x660000
IDLCK_LO, IDLCK_HI = 0x61E29F, 0x61E3C5

off_lo = va_to_off(SCAN_LO)
code = data[off_lo:off_lo + (SCAN_HI - SCAN_LO)]

# Single linear pass, keeping a rolling window of decoded instructions.
insns = []
pos = 0
size = len(code)
while pos < size:
    got = False
    for insn in md.disasm(code[pos:pos + 0x2000], SCAN_LO + pos):
        insns.append((insn.address, insn.size, insn.mnemonic, insn.op_str,
                      insn.bytes))
        got = True
        pos = insn.address - SCAN_LO + insn.size
        if pos >= size:
            break
    if not got:
        pos += 1

print(f"decoded {len(insns)} instructions in 0x{SCAN_LO:X}-0x{SCAN_HI:X}\n")

def is_shift3(mn, ops):
    return mn in ('sar', 'shr') and ops.endswith(', 3')

def is_and7(mn, ops):
    return mn == 'and' and ops.endswith(', 7')

candidates = []
for i, (va, sz, mn, ops, raw) in enumerate(insns):
    if not is_shift3(mn, ops):
        continue
    lo = max(0, i - 20)
    hi = min(len(insns), i + 20)
    window = insns[lo:hi]
    has_and7 = any(is_and7(m, o) for _, _, m, o, _ in window)
    has_byte_mem = any(('byte ptr [' in o) for _, _, m, o, _ in window)
    if has_and7 and has_byte_mem:
        candidates.append((va, lo, hi))

print(f"{len(candidates)} candidate site(s) with sar/shr-3 + and-7 + byte access:\n")
last_end = 0
for va, lo, hi in candidates:
    if lo < last_end:          # merge overlapping windows in output
        lo = last_end
    tag = "  (the IDLCK handler -- detector validation)" \
        if IDLCK_LO <= va <= IDLCK_HI else ""
    print(f"--- candidate around 0x{va:08X}{tag} ---")
    for a, s, m, o, r in insns[lo:hi]:
        print(f"    0x{a:08X}  {m:<8} {o}")
    last_end = hi
    print()
