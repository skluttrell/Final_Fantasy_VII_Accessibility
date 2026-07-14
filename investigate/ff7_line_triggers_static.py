#!/usr/bin/env python3
"""
ff7_line_triggers_static.py -- Statically locate the runtime storage of field
LINE trigger zones (script-opcode lines: ladders, elevators, touch/cross
zones) in ff7_en.exe on disk (2026-07-14).

WHY:
  Next pathfinder category ("Triggers"): the v2.14-v2.16 browser covers
  gateways (section-8 exits) and people (field models), but the third kind of
  interactable -- LINE entities created by the field script -- is invisible to
  a blind player. Lines are how the game implements ladders (LADER opcode
  runs when the player activates one), elevators, and script zones that fire
  on touch/cross. Sighted players infer them from the scenery; the pathfinder
  should list them with the same direction/distance math exits use.

  Field scripts create lines with three opcodes (FFNx FieldOpcode enum,
  values confirmed by counting the enum blocks -- MESSAGE=0x40/ASK=0x48
  match the known table entries the mod already hooks):

      LINE  = 0xD0  (entity declares itself a line: 6 shorts, X1Y1Z1 X2Y2Z2)
      LINON = 0xD1  (enable/disable an existing line: 1 byte arg)
      SLINE = 0xD3  (move/redefine a line with bank-addressable args)

  The HANDLERS for these opcodes must write the vertices + enable flag into
  whatever runtime array the collision test reads every frame. Finding that
  array statically = disassembling the handlers.

HOW (all from the exe on disk -- zero live process interaction):
  1. execute_opcode_table via the mod's own Resolve() chain (ff7_data.h):
         execute_opcode       = grc(field_init_event_60BACF, 0x80)
         execute_opcode_table = gav(execute_opcode, 0x10D)
     The table is a static initialized array, so its entries are readable
     from the file image.
  2. Cross-checks before trusting anything:
       - table[0x40] (MESSAGE) must be an exe-range code address AND have an
         E8 CALL byte at +0x3B -- the exact validation FFNx's
         ff7_find_externals performs on the same entry (the v1.0 crash
         lesson documented in ff7_addresses.cpp).
       - table[0x48] (ASK) must be an exe-range code address.
  3. Disassemble the LINE/LINON/SLINE handlers (capstone, 32-bit) with every
     absolute-address memory operand marked, plus a per-handler summary of
     written globals and indexed-array (base + reg*scale) patterns. The
     common write target across all three handlers is the line array; the
     LINON-only byte write is the enable flag.

Output: annotated listings + summary. Feeds ff7_line_triggers_verify.py
(live dump of the discovered array) before anything ships in the mod.

Requires capstone (already in investigate/venv).
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
    f"line_triggers_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
# Always restore stdout and close the log, whatever the exit path (rule:
# feedback_investigation_scripts.md; atexit runs on exceptions and Ctrl+C).
import atexit
def _restore_stdout():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore_stdout)
print(f"Output saving to: {_log_path}\n")

# -- locate the exe on disk ------------------------------------------------------
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
    # 2026 rerelease install first (the one this project targets), 2013 second.
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

# -- minimal PE parse (same pattern as ff7_field_triggers_static.py) ------------
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
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    sections.append((va, vs, rp))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

def grc(addr, offset):
    """FFNx get_relative_call: E8 rel32 at addr+offset -> call target."""
    off = va_to_off(addr + offset)
    if off is None or data[off] != 0xE8:
        return None
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return addr + offset + 5 + rel

def gav(addr, offset):
    """FFNx get_absolute_value: u32 immediate at addr+offset."""
    off = va_to_off(addr + offset)
    return struct.unpack_from('<I', data, off)[0] if off is not None else None

CODE_LO, CODE_HI = 0x401000, 0x9FFFFF

# -- Step 1: resolve the opcode table (the mod's own Resolve() chain) -----------
FIELD_INIT_EVENT = 0x60BACF
execute_opcode = grc(FIELD_INIT_EVENT, 0x80)
print(f"execute_opcode       = grc(0x{FIELD_INIT_EVENT:X}, 0x80)  = "
      f"{'0x%08X' % execute_opcode if execute_opcode else 'FAIL'}")
if not execute_opcode or not (CODE_LO <= execute_opcode <= CODE_HI):
    print("CHAIN INVALID -- execute_opcode out of range, aborting.")
    sys.exit(1)

table_va = gav(execute_opcode, 0x10D)
print(f"execute_opcode_table = gav(^, 0x10D)            = 0x{table_va:08X}")
table_off = va_to_off(table_va)
if table_off is None:
    print("CHAIN INVALID -- table VA not in any section, aborting.")
    sys.exit(1)

entries = struct.unpack_from('<256I', data, table_off)

# -- Step 2: cross-checks --------------------------------------------------------
msg = entries[0x40]
ask = entries[0x48]
msg_ok = CODE_LO <= msg <= CODE_HI
call_ok = msg_ok and data[va_to_off(msg + 0x3B)] == 0xE8   # FFNx's own walk
ask_ok = CODE_LO <= ask <= CODE_HI
print(f"\nCross-checks:")
print(f"  table[0x40] MESSAGE = 0x{msg:08X}  in exe code range          {'OK' if msg_ok else '** FAIL **'}")
print(f"  byte at MESSAGE+0x3B = 0x{data[va_to_off(msg + 0x3B)]:02X}  expect E8 (FFNx walk)      {'OK' if call_ok else '** FAIL **'}")
print(f"  table[0x48] ASK     = 0x{ask:08X}  in exe code range          {'OK' if ask_ok else '** FAIL **'}")
if not (msg_ok and call_ok and ask_ok):
    print("CROSS-CHECKS FAILED -- do not trust the table, aborting.")
    sys.exit(1)
print("ALL CROSS-CHECKS PASSED.\n")

# -- Step 3: disassemble the line-opcode handlers --------------------------------
TARGETS = [
    (0xD0, "LINE",  "declare line (6 short args: X1 Y1 Z1 X2 Y2 Z2)"),
    (0xD1, "LINON", "enable/disable line (1 byte arg)"),
    (0xD3, "SLINE", "move/redefine line (bank-addressable args)"),
    (0xC2, "LADER", "ladder move (context only -- how lines get used)"),
]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_handler(va, max_bytes=0x600):
    """Linear disassembly from va, extending past RETs that have forward
    jumps beyond them (compact handler heuristic). Returns (lines, writes,
    reads, indexed) where writes/reads are {abs_addr: [va,...]} for absolute
    [imm32] operands and indexed is [(disp, scale, va)] for base-less
    reg-indexed operands (array candidates)."""
    off = va_to_off(va)
    code = data[off:off + max_bytes]
    lines, writes, reads, indexed = [], {}, {}, []
    max_fwd = va          # furthest forward jump target seen
    end_va = va + max_bytes
    for insn in md.disasm(code, va):
        markers = []
        # Forward-jump tracking so we don't stop at an early RET.
        if insn.group(capstone.CS_GRP_JUMP) and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            tgt = insn.operands[0].imm
            if va < tgt < end_va:
                max_fwd = max(max_fwd, tgt)
        for i, op in enumerate(insn.operands):
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            m = op.mem
            if m.base == 0 and m.index == 0 and m.disp > 0x400000:
                # Absolute global. Operand 0 of a writing insn = store.
                is_write = (i == 0 and insn.mnemonic.startswith(
                    ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                d = writes if is_write else reads
                d.setdefault(m.disp, []).append(insn.address)
                markers.append(f"{'W' if is_write else 'R'} GLOBAL[0x{m.disp:08X}]")
            elif m.base == 0 and m.index != 0 and m.disp > 0x400000:
                # disp + reg*scale with no base register = static array.
                indexed.append((m.disp, m.scale, insn.address))
                markers.append(f"ARRAY[0x{m.disp:08X} + reg*{m.scale}]")
        lines.append(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}"
                     + (f"   ; {' | '.join(markers)}" if markers else ""))
        if insn.mnemonic.startswith('ret') and insn.address >= max_fwd:
            break
    return lines, writes, reads, indexed

for opc, name, desc in TARGETS:
    va = entries[opc]
    print(f"{'='*74}")
    print(f"table[0x{opc:02X}] {name} = 0x{va:08X}   ({desc})")
    print(f"{'='*74}")
    if not (CODE_LO <= va <= CODE_HI):
        print("  ** handler address out of exe range -- skipped **\n")
        continue
    lines, writes, reads, indexed = disasm_handler(va)
    for ln in lines:
        print(ln)
    print(f"\n  -- {name} summary --")
    if writes:
        for a in sorted(writes):
            print(f"  WRITES GLOBAL 0x{a:08X}  at {', '.join('0x%X' % x for x in writes[a])}")
    if indexed:
        seen = set()
        for disp, scale, at in indexed:
            if (disp, scale) in seen:
                continue
            seen.add((disp, scale))
            print(f"  INDEXED ARRAY base=0x{disp:08X} scale={scale}  (first at 0x{at:X})")
    if reads:
        print(f"  reads: {', '.join('0x%08X' % a for a in sorted(reads))}")
    if not (writes or indexed):
        print("  (no absolute stores found -- storage is behind a register-held"
              " pointer; inspect the listing for the pointer's source global)")
    print()

print(f"{'='*74}")
print("NEXT STEP: intersect LINE's write targets with LINON's -- the shared")
print("base is the line array; LINON's byte-sized store is the enable flag.")
print("Then live-verify with ff7_line_triggers_verify.py before shipping.")
print(f"\nLog saved to: {_log_path}")
_log_file.close()
