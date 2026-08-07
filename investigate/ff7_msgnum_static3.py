#!/usr/bin/env python3
"""
ff7_msgnum_static3.py -- FE DE number mechanism, part 3 (2026-08-07;
PARKED [DIALOGNUM] + [INNGIL]; companion to parts 1/2).

Part 2 found the typewriter's function-code machinery (window index in
[ebp+8], all arrays win-indexed):
  0xCBFC00 + win*2   s16  digit-emit index, -1 = not emitting
  0xCBFBA0 + win*16  u8   formatted digit buffer, 0xFF-terminated
  0xCC0EC0 + win*2   u16  counter incremented AFTER each completed
                          number -- suspected occurrence->slot rule
  0xCC0428 + win*256      the window's rendered text buffer (digits are
                          stored there char by char as they type)
  helper 0x632FFB(win) -> ax = the VALUE that gets formatted
  formatters: 0x633433 (FE DE decimal), 0x6335D3 (FE DF), 0x6334F0 (FE E1)

THIS SCRIPT closes the loop:
  1. Full disasm of 0x632FFB -- expect it to read the MPARA param array
     word [0xCC08A0 + win*16 + slot*2] with slot = [0xCC0EC0 + win*2],
     and, when the bank byte [0xCBFBE0 + win*8 + slot] is nonzero,
     re-resolve the live script variable instead (find that call).
  2. Full disasm of the three formatters (arg meaning + terminator).
  3. imm32 sweep for 0xCC0EC0 refs -- who RESETS the occurrence counter
     (window open? page turn?) -- the mod must mirror the same reset
     rule when it maps FE DE occurrences to slots at decode time.
"""
import sys, os, struct, datetime, subprocess

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed. Run: venv/Scripts/python.exe -m pip install capstone")
    sys.exit(1)

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"msgnum_static3_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    name = data[off:off+8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    sections.append((name, va, vs, rs, rp))

def va_to_off(va):
    rva = va - image_base
    for _, sva, svs, _, srp in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

INTEREST = {
    (0xCC08A0, 0xCC08A0 + 0x100): "MPARA-PARAM",
    (0xCBFBE0, 0xCBFBE0 + 0x80):  "MPARA-BANK",
    (0xCBFBA0, 0xCBFBA0 + 0x40):  "DIGITBUF",
    (0xCBFC00, 0xCBFC00 + 0x10):  "EMIT-IDX",
    (0xCC0EC0, 0xCC0EC0 + 0x10):  "OCC-CTR",
    (0xCBF578, 0xCBF588):         "TXTPTR",
    (0xCC0428, 0xCC0428 + 1):     "RENDERBUF",
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
            for (lo, hi), tag in INTEREST.items():
                if lo <= v < hi:
                    notes.append(f"{tag} 0x{v:08X}")
    return ("   ; <<< " + ", ".join(notes)) if notes else ""

def disasm_full(va, label, max_insns=400):
    print("=" * 74)
    print(f"{label} @ 0x{va:08X}")
    print("=" * 74)
    off = va_to_off(va)
    calls = []
    n = 0
    for insn in md.disasm(bytes(data[off:off + 0x1200]), va):
        if insn.mnemonic == 'call' and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            calls.append(insn.operands[0].imm & 0xFFFFFFFF)
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}")
        n += 1
        if insn.mnemonic == 'ret' or n >= max_insns:
            break
    print()
    return calls

# Step 1+2: the value helper and the three formatters.
calls = disasm_full(0x632FFB, "value helper 0x632FFB(win)")
for c in sorted(set(calls)):
    if 0x401000 <= c <= 0x9FFFFF:
        disasm_full(c, f"  helper-of-helper 0x{c:08X}", max_insns=150)
disasm_full(0x633433, "formatter FE DE (decimal) 0x633433", max_insns=200)
disasm_full(0x6334F0, "formatter FE E1 0x6334F0", max_insns=200)
disasm_full(0x6335D3, "formatter FE DF 0x6335D3", max_insns=200)

# Step 3: who touches the occurrence counter 0xCC0EC0?
text = next(s for s in sections if s[0] == '.text')
_, t_va, t_vs, t_rs, t_rp = text
t_size = min(t_vs, t_rs)
raw = data[t_rp:t_rp + t_size]
print("=" * 74)
print("references to OCC-CTR 0xCC0EC0..0xCC0ECF across .text")
print("=" * 74)
hits = []
for i in range(t_size - 3):
    v = int.from_bytes(raw[i:i+4], 'little')
    if 0xCC0EC0 <= v < 0xCC0ED0:
        hits.append(image_base + t_va + i)
for site in hits:
    lo = site - 0x28
    off = va_to_off(lo)
    print(f"\n-- ref at 0x{site:08X} (context) --")
    for insn in md.disasm(bytes(data[off:off + 0x50]), lo):
        mark = "  <== ref" if insn.address <= site < insn.address + insn.size else ""
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}{mark}")
        if insn.address > site + 8:
            break
print("\nDone.")
