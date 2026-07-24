#!/usr/bin/env python3
"""
ff7_idlck_readers.py -- Phase 2 of the triangle-lock investigation: find the
READ side of the IDLCK bitfield (2026-07-23).

Phase 1 (ff7_idlck_static.py, log idlck_static_20260723_201129.log) proved
the IDLCK handler (0x61E29F) stores per-triangle lock state as a BITFIELD:

    byte [ [0xCBF9D8] + 0xB2 + (triangle_id >> 3) ]  bit (triangle_id & 7)
    flag!=0 -> OR in the bit (lock);  flag==0 -> AND it out (unlock)

The lock lives behind the field-global-object POINTER, not at a static
address, so the phase-1 imm32 xref scan couldn't see its consumers. The
access signature is distinctive though: a byte access at displacement 0xB2
with BOTH a base register (the object pointer) and an index register (the
byte index) -- `byte ptr [reg + reg + 0xB2]`. This script disassembles ALL
executable sections linearly and reports every instruction with a mem
operand whose disp == 0xB2 and base+index both present, plus a context
window around each hit so the surrounding function is identifiable
(movement/collision code vs. the IDLCK handler itself vs. unrelated structs
that happen to have a +0xB2 field -- the context and the >>3/&7 arithmetic
nearby tell them apart).

Requires capstone (already in investigate/venv).
"""
import sys, os, struct, datetime, subprocess

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed.")
    sys.exit(1)

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"idlck_readers_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# Field module code range (from the region map: 0x60xxxx-0x6Exxxx) is where
# collision/movement lives; scan the whole exe anyway and let the report
# group by range.
IDLCK_HANDLER = 0x61E29F

hits = []
for sva, svs, srp, srs, flags in sections:
    if not (flags & 0x20000000):
        continue
    size = min(svs, srs)
    base_va = image_base + sva
    code = data[srp:srp + size]
    # Linear disassembly of the whole section, resynchronizing after invalid
    # bytes (skip 1 byte on failure) -- crude but exhaustive for a scan.
    pos = 0
    while pos < size:
        found_any = False
        for insn in md.disasm(code[pos:pos + 0x1000], base_va + pos):
            found_any = True
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    m = op.mem
                    if m.disp == 0xB2 and m.base != 0 and m.index != 0:
                        hits.append(insn.address)
            pos = insn.address - base_va + insn.size
            if pos >= size:
                break
        if not found_any:
            pos += 1

print(f"\n{len(hits)} instruction(s) with [reg + reg + 0xB2] operands:\n")

def disasm_context(va, before=0x30, after=0x30):
    # Find a section containing va
    for sva, svs, srp, srs, flags in sections:
        base_va = image_base + sva
        if base_va <= va < base_va + min(svs, srs):
            start = va - before
            off = srp + (start - base_va)
            out = []
            for insn in md.disasm(data[off:off + before + after], start):
                mark = "  <=== HIT" if insn.address == va else ""
                out.append(f"    0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{mark}")
                if insn.address > va + after - 16:
                    break
            return out
    return []

for h in hits:
    in_idlck = IDLCK_HANDLER <= h <= IDLCK_HANDLER + 0x130
    print(f"HIT at 0x{h:08X}{'  (inside the IDLCK handler itself)' if in_idlck else ''}")
    if not in_idlck:
        for line in disasm_context(h):
            print(line)
    print()

print("Interpretation guide: a hit OUTSIDE the IDLCK handler whose context")
print("shows the >>3 / &7 bit math and a read of [0xCBF9D8] is the game's")
print("own lock CONSUMER -- its surrounding function is the movement/")
print("collision path, and its test polarity (jz/jnz after the bit test)")
print("confirms bit=1 means impassable.")
