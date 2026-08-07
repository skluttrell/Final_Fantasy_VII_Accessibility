#!/usr/bin/env python3
"""
ff7_msgnum_static.py -- Statically derive the FE DE in-dialog NUMBER
mechanism (2026-08-07; PARKED [DIALOGNUM] + [INNGIL]).

WHY:
  v2.30.91's log work proved the numbers a dialog displays ("Here's the
  squats you managed 6." / "It's 10 gil a night.") are NEVER in the text
  bytes -- the byte stream carries the function code FE DE where the
  digits render (log.6 20:32:46 / 20:33:20, log.5 14:29:34). The mod
  therefore cannot speak them from the rawptr decode alone; it needs the
  engine's message-variable source.

WHAT IS ALREADY KNOWN (mpnam_static_20260716_194059.log, neighbor
context disasm of the same opcode table):
  MPARA  = table[0x41] @ 0x0061F2B0
  MPRA2  = table[0x42] @ 0x0061F377
  Both resolve a window id from the script args and write
    byte [0xCBFBE0 + slot + win*8]       (bank nibble)
    word [0xCC08A0 + win*16 + slot*2]    (value)
  -- i.e. per-window arrays of up to 8 numeric parameters. What that log
  did NOT capture (it was cut at 40 instructions and MPARA was only
  "bonus context"): the exact argument layout (where SLOT comes from),
  the semantics of helper call 0x60F750, and -- the critical half -- the
  RENDER side: which code reads 0xCC08A0 when the typewriter hits FE DE,
  and how it picks the slot for each occurrence (the squats final score
  has TWO FE DE in one window with two different values, so slots must
  be distinguishable per occurrence).

HOW (exe on disk, zero live interaction -- v2.17 chain):
  1. execute_opcode_table via grc(0x60BACF,0x80) -> gav(^,0x10D), with
     the MESSAGE/ASK cross-checks before trusting anything.
  2. FULL disassembly of table[0x41]/table[0x42] to ret (write summary +
     every absolute global).
  3. Disassemble the first helper each handler calls (expected 0x60F750,
     the script-argument resolver) -- its return value's meaning decides
     whether slot comes from an opcode byte or a computed value.
  4. Sweep .text for imm32 references into 0xCC08A0..+0x100 and
     0xCBFBE0..+0x80; every hit OUTSIDE the two handlers is a candidate
     reader. Disassemble a context window around each and flag compares
     against 0xFE/0xDE/0xDF (the function-code dispatch) plus any index
     arithmetic (*2 with win*16) that reveals the slot rule.

Output feeds the v2.30.92 implementation: read the per-window params at
PENDING time and substitute the values where FE DE sits in the decode.
"""
import sys, os, struct, datetime, subprocess

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed. Run: venv/Scripts/python.exe -m pip install capstone")
    sys.exit(1)

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"msgnum_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- locate the exe on disk (same candidates as prior static scripts) ------------
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

# -- minimal PE parse -------------------------------------------------------------
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

def grc(addr, offset):
    off = va_to_off(addr + offset)
    if off is None or data[off] != 0xE8:
        return None
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return addr + offset + 5 + rel

def gav(addr, offset):
    off = va_to_off(addr + offset)
    return struct.unpack_from('<I', data, off)[0] if off is not None else None

CODE_LO, CODE_HI = 0x401000, 0x9FFFFF

# -- Step 1: opcode table + cross-checks (identical to v2.17/mpnam) --------------
FIELD_INIT_EVENT = 0x60BACF
execute_opcode = grc(FIELD_INIT_EVENT, 0x80)
print(f"execute_opcode       = grc(0x{FIELD_INIT_EVENT:X}, 0x80)  = "
      f"{'0x%08X' % execute_opcode if execute_opcode else 'FAIL'}")
if not execute_opcode or not (CODE_LO <= execute_opcode <= CODE_HI):
    print("CHAIN INVALID -- aborting.")
    sys.exit(1)
table_va = gav(execute_opcode, 0x10D)
print(f"execute_opcode_table = gav(^, 0x10D)            = 0x{table_va:08X}")
table_off = va_to_off(table_va)
entries = struct.unpack_from('<256I', data, table_off)

msg = entries[0x40]
ask = entries[0x48]
msg_ok = CODE_LO <= msg <= CODE_HI
call_ok = msg_ok and data[va_to_off(msg + 0x3B)] == 0xE8
ask_ok = CODE_LO <= ask <= CODE_HI
print(f"\nCross-checks:")
print(f"  table[0x40] MESSAGE = 0x{msg:08X}  {'OK' if msg_ok else '** FAIL **'}")
print(f"  MESSAGE+0x3B byte = 0x{data[va_to_off(msg + 0x3B)]:02X} expect E8  {'OK' if call_ok else '** FAIL **'}")
print(f"  table[0x48] ASK     = 0x{ask:08X}  {'OK' if ask_ok else '** FAIL **'}")
if not (msg_ok and call_ok and ask_ok):
    print("CROSS-CHECKS FAILED -- aborting.")
    sys.exit(1)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

PARAM_BASE = 0xCC08A0   # word [win*16 + slot*2] -- values
BANK_BASE  = 0xCBFBE0   # byte [win*8  + slot]   -- bank nibbles
PARAM_HI   = PARAM_BASE + 0x100
BANK_HI    = BANK_BASE + 0x80

def imm_globals(insn):
    """Yield every imm/disp in the interesting global range."""
    out = []
    for op in insn.operands:
        if op.type == capstone.x86.X86_OP_IMM:
            out.append(op.imm & 0xFFFFFFFF)
        elif op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
            out.append(op.mem.disp & 0xFFFFFFFF)
    return out

def disasm_full(va, label, max_insns=260):
    """Linear disassembly from va to the first ret (or cap). Returns
    (call_targets, writes) where writes = (insn_va, text) touching the
    param/bank arrays."""
    print("=" * 74)
    print(f"{label} @ 0x{va:08X}")
    print("=" * 74)
    off = va_to_off(va)
    calls, hits = [], []
    count = 0
    for insn in md.disasm(bytes(data[off:off + 0x900]), va):
        note = ""
        for g in imm_globals(insn):
            if PARAM_BASE <= g < PARAM_HI or BANK_BASE <= g < BANK_HI:
                which = "PARAM" if g >= PARAM_BASE else "BANK"
                note = f"   ; <<< {which} array 0x{g:08X}"
                hits.append((insn.address, f"{insn.mnemonic} {insn.op_str}"))
        if insn.mnemonic == 'call' and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            calls.append(insn.operands[0].imm & 0xFFFFFFFF)
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{note}")
        count += 1
        if insn.mnemonic == 'ret' or count >= max_insns:
            break
    print()
    return calls, hits

# -- Step 2: full MPARA / MPRA2 disassembly ---------------------------------------
mpara = entries[0x41]
mpra2 = entries[0x42]
print(f"\ntable[0x41] MPARA = 0x{mpara:08X}")
print(f"table[0x42] MPRA2 = 0x{mpra2:08X}\n")
mpara_calls, _ = disasm_full(mpara, "MPARA (full)")
mpra2_calls, _ = disasm_full(mpra2, "MPRA2 (full)")

# -- Step 3: the shared helper (script-argument resolver) -------------------------
helpers = sorted(set(mpara_calls) | set(mpra2_calls))
print(f"Helper calls from MPARA/MPRA2: {['0x%08X' % h for h in helpers]}\n")
for h in helpers:
    if CODE_LO <= h <= CODE_HI:
        disasm_full(h, f"helper 0x{h:08X} (script-arg resolver?)", max_insns=120)

# -- Step 4: sweep .text for readers of the param/bank arrays ---------------------
text = next(s for s in sections if s[0] == '.text')
_, t_va, t_vs, t_rs, t_rp = text
t_size = min(t_vs, t_rs)
print("=" * 74)
print(f"imm32 sweep of .text (0x{image_base + t_va:08X}..+0x{t_size:X}) for "
      f"[0x{PARAM_BASE:08X},0x{PARAM_HI:08X}) and [0x{BANK_BASE:08X},0x{BANK_HI:08X})")
print("=" * 74)
raw = data[t_rp:t_rp + t_size]
hits = []
for i in range(t_size - 3):
    v = int.from_bytes(raw[i:i+4], 'little')
    if PARAM_BASE <= v < PARAM_HI or BANK_BASE <= v < BANK_HI:
        hits.append((image_base + t_va + i, v))
print(f"{len(hits)} raw imm32 hits\n")

# Group hits into clusters (>0x40 apart = new site) and skip the two
# handlers we already dumped.
known = [(mpara, mpara + 0x120), (mpra2, mpra2 + 0x140)]
clusters = []
for site, v in hits:
    if any(lo <= site < hi for lo, hi in known):
        continue
    if clusters and site - clusters[-1][-1][0] <= 0x40:
        clusters[-1].append((site, v))
    else:
        clusters.append([(site, v)])
print(f"{len(clusters)} candidate reader cluster(s) outside MPARA/MPRA2:\n")

for ci, cl in enumerate(clusters):
    lo = cl[0][0] - 0x70
    hi = cl[-1][0] + 0x90
    print("=" * 74)
    print(f"cluster {ci}: {len(cl)} ref(s) "
          f"{['0x%08X->0x%08X' % (s, v) for s, v in cl]}")
    print("=" * 74)
    # Linear disasm from a bit before the first ref; x86 self-syncs
    # within a few instructions -- the refs themselves anchor validity.
    off = va_to_off(lo)
    fe_notes = 0
    for insn in md.disasm(bytes(data[off:off + (hi - lo)]), lo):
        note = ""
        for g in imm_globals(insn):
            if PARAM_BASE <= g < PARAM_HI:
                note = f"   ; <<< PARAM 0x{g:08X}"
            elif BANK_BASE <= g < BANK_HI:
                note = f"   ; <<< BANK 0x{g:08X}"
        # flag function-code dispatch compares
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM and op.imm in (0xFE, 0xDE, 0xDF, 0xDD, 0xD2, 0xE2):
                note += f"   ; <<< cmp-const 0x{op.imm & 0xFF:02X}"
                fe_notes += 1
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{note}")
        if insn.address >= hi:
            break
    print(f"  [{fe_notes} function-code constant(s) flagged in this window]\n")

print("Done. Feed the reader cluster(s) into the v2.30.92 design: the slot")
print("rule is whatever index arithmetic the reader applies to PARAM/BANK.")
