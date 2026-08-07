#!/usr/bin/env python3
"""
ff7_wnumb_static.py -- Statically derive the WSPCL type-2 NUMERIC window
value source (2026-08-07; PARKED [INNSTAY], follow-on to the v2.30.92
FE DE session).

WHY:
  The inn's "Sleep for how long?" amount selector is a WSPCL id=3
  type=2 window (log.5 14:31:39 / log.6 20:52:33: the mod's v2.30.56
  WSPCL hook logs it arming; the dialog text decodes EMPTY -- the
  number lives in the special-window system, not the text). To speak
  the selector's value (and its changes as the player presses Up/
  Down), the mod needs to know where that value lives and whether the
  window SNAPSHOTS it (script re-fires WNUMB per press) or stays
  LIVE-BOUND to a script variable the renderer re-reads each frame.

WHAT IS KNOWN:
  - WNUMB = opcode 0x37 (cebix canonical length table: 7 bytes --
    opcode, bank byte, window, u32 value), sitting between WSPCL 0x36
    and STTIM 0x38, both already hooked by the mod (same table).
  - WSPCL handler 0x61FD5C writes the type byte [0xCFF5D3+win*0x30]
    (v2.30.56 map row).
  - The v2.30.92 session mapped the script-variable banks (regions at
    0xDC08DC, temp bank 0xCC14D0) -- if WNUMB's bank byte works like
    MPARA's, the same resolver applies.

HOW (exe on disk, zero live interaction -- the v2.17 chain + msgnum
session patterns):
  1. execute_opcode_table via grc(0x60BACF,0x80) -> gav(^,0x10D) with
     the MESSAGE/ASK cross-checks; extra cross-check: table[0x36]
     should equal the known WSPCL handler 0x61FD5C.
  2. FULL disasm of table[0x37] WNUMB: argument reads, every global
     WRITE (the value store), helper calls (expect the 0x60F750-style
     script-arg resolver if bank-dispatched).
  3. FULL disasm of table[0x36] WSPCL for side-by-side context.
  4. Auto-sweep: collect WNUMB's data-range write targets, sweep
     .text for imm32 references to them, dump every reader context --
     the type-2 renderer. Flag reads of the window type byte family
     (0xCFF5C8..0xCFF6xx, stride 0x30), digit-ish constants (0x2F/
     0x30 glyph math, divide-by-10 magic 0x66666667), and the
     v2.30.92 script-bank bases (re-read each frame = live binding).

Output feeds the [INNSTAY] implementation: hook table[0x37] vs poll
the discovered global, plus the choice-cue arming rule.
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
    f"wnumb_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

msg, ask = entries[0x40], entries[0x48]
wspcl, wnumb, sttim = entries[0x36], entries[0x37], entries[0x38]
msg_ok  = CODE_LO <= msg <= CODE_HI
call_ok = msg_ok and data[va_to_off(msg + 0x3B)] == 0xE8
ask_ok  = CODE_LO <= ask <= CODE_HI
wspcl_ok = (wspcl == 0x61FD5C)
print(f"\nCross-checks:")
print(f"  table[0x40] MESSAGE = 0x{msg:08X}  {'OK' if msg_ok else '** FAIL **'}")
print(f"  MESSAGE+0x3B byte = 0x{data[va_to_off(msg + 0x3B)]:02X} expect E8  {'OK' if call_ok else '** FAIL **'}")
print(f"  table[0x48] ASK     = 0x{ask:08X}  {'OK' if ask_ok else '** FAIL **'}")
print(f"  table[0x36] WSPCL   = 0x{wspcl:08X}  expect 0x0061FD5C (v2.30.56)  "
      f"{'OK' if wspcl_ok else '** FAIL **'}")
print(f"  table[0x37] WNUMB   = 0x{wnumb:08X}")
print(f"  table[0x38] STTIM   = 0x{sttim:08X}  (mod-hooked)")
if not (msg_ok and call_ok and ask_ok and wspcl_ok):
    print("CROSS-CHECKS FAILED -- aborting.")
    sys.exit(1)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

DATA_LO, DATA_HI = 0xC00000, 0xE80000
# v2.30.92 landmarks worth annotating anywhere they appear:
LANDMARKS = {
    (0xDC08DC, 0xDC0DDC): "SCRIPT_VAR region",
    (0xCC14D0, 0xCC15D0): "SCRIPT_TEMP bank",
    (0xCFF5C8, 0xCFF6F8): "window-struct family (0x30 stride)",
    (0xCBF578, 0xCBF588): "TXTPTR",
    (0xCC08A0, 0xCC08E0): "MSG_NUM_PARAMS",
    (0xCBFBE0, 0xCBFC10): "MSG_NUM_BANKS",
    (0xDC093B, 0xDC093C): "game-timer byte family (v2.30.56)",
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
            for (lo, hi), tag in LANDMARKS.items():
                if lo <= v < hi:
                    notes.append(f"{tag} 0x{v:08X}")
        if op.type == capstone.x86.X86_OP_IMM and (op.imm & 0xFFFFFFFF) == 0x66666667:
            notes.append("div-by-10 magic")
    return ("   ; <<< " + ", ".join(notes)) if notes else ""

def disasm_full(va, label, max_insns=400, collect_writes=None):
    print("=" * 74)
    print(f"{label} @ 0x{va:08X}")
    print("=" * 74)
    off = va_to_off(va)
    calls = []
    n = 0
    for insn in md.disasm(bytes(data[off:off + 0x1400]), va):
        note = annotate(insn)
        # record data-range mem WRITE targets (first operand is dest)
        if collect_writes is not None and insn.operands and \
           insn.mnemonic.startswith(('mov', 'or', 'and', 'add', 'sub', 'inc', 'dec')) and \
           insn.operands[0].type == capstone.x86.X86_OP_MEM and \
           insn.operands[0].mem.disp:
            d = insn.operands[0].mem.disp & 0xFFFFFFFF
            if DATA_LO <= d < DATA_HI:
                collect_writes.add(d)
                note += f"   ; WRITE -> 0x{d:08X}"
        if insn.mnemonic == 'call' and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            calls.append(insn.operands[0].imm & 0xFFFFFFFF)
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{note}")
        n += 1
        if insn.mnemonic == 'ret' or n >= max_insns:
            break
    print()
    return calls

# -- Step 2: WNUMB full disasm -----------------------------------------------------
wnumb_writes = set()
wnumb_calls = disasm_full(wnumb, "WNUMB (table[0x37], full)", collect_writes=wnumb_writes)
print(f"WNUMB data-range write targets: {['0x%08X' % w for w in sorted(wnumb_writes)]}")
print(f"WNUMB helper calls: {['0x%08X' % c for c in sorted(set(wnumb_calls))]}\n")
for c in sorted(set(wnumb_calls)):
    if CODE_LO <= c <= CODE_HI:
        disasm_full(c, f"  WNUMB helper 0x{c:08X}", max_insns=140)

# -- Step 3: WSPCL for context ------------------------------------------------------
wspcl_writes = set()
disasm_full(wspcl, "WSPCL (table[0x36], full -- context)", collect_writes=wspcl_writes)
print(f"WSPCL data-range write targets: {['0x%08X' % w for w in sorted(wspcl_writes)]}\n")

# -- Step 4: sweep for readers of the WNUMB write targets --------------------------
text = next(s for s in sections if s[0] == '.text')
_, t_va, t_vs, t_rs, t_rp = text
t_size = min(t_vs, t_rs)
raw = data[t_rp:t_rp + t_size]

targets = sorted(wnumb_writes)
if not targets:
    print("No WNUMB write targets found -- nothing to sweep.")
    sys.exit(0)

print("=" * 74)
print("imm32 sweep of .text for every WNUMB write target (readers = the")
print("type-2 renderer / consumers)")
print("=" * 74)
hits = []
tset = set(targets)
# also catch base-adjacent refs (arrays indexed from a nearby base)
tnear = set()
for t in targets:
    for d in range(-0x10, 0x14, 2):
        tnear.add(t + d)
for i in range(t_size - 3):
    v = int.from_bytes(raw[i:i+4], 'little')
    if v in tnear:
        hits.append((image_base + t_va + i, v))
print(f"{len(hits)} raw hits (exact + near-base)\n")

# cluster and dump
clusters = []
for s, v in hits:
    if clusters and s - clusters[-1][-1][0] <= 0x60:
        clusters[-1].append((s, v))
    else:
        clusters.append([(s, v)])
print(f"{len(clusters)} reader/writer cluster(s):\n")
for ci, cl in enumerate(clusters):
    lo = (cl[0][0] - 0x90) & ~0xF
    hi = cl[-1][0] + 0xB0
    inside_wnumb = wnumb <= cl[0][0] < wnumb + 0x200
    print("=" * 74)
    print(f"cluster {ci}: {len(cl)} ref(s) "
          f"{['0x%08X->0x%08X' % (s, v) for s, v in cl]}"
          f"{'   [inside WNUMB handler itself]' if inside_wnumb else ''}")
    print("=" * 74)
    if inside_wnumb:
        print("  (already dumped above)\n")
        continue
    off = va_to_off(lo)
    for insn in md.disasm(bytes(data[off:off + (hi - lo)]), lo):
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}")
        if insn.address >= hi:
            break
    print()

print("Done. The reader cluster that formats digits (div-by-10 magic or")
print("0x10-0x19 FF7 digit bytes) is the type-2 renderer; whether it reads")
print("the stored value or a script-bank base decides snapshot vs live.")
