#!/usr/bin/env python3
"""
ff7_mpnam_static.py -- Statically locate where the engine stores the
FRIENDLY map/location name ("Sector 1 Station") that the main menu
displays (2026-07-16; TODO.txt "[NAV] Friendly map names").

WHY:
  The v2.23 screen-change announcement and the M key speak internal field
  names ("nmkin 2"). The friendly name shown at the bottom of the main
  menu is set by the field script opcode MPNAM. The live scan
  (ff7_location_name_scan.py, same day) PROVED the savemap preview block
  at savemap+0x00..0x53 stays all-zero during play — the preview is only
  generated at save time — so the live copy is wherever the MPNAM handler
  puts it.

  MPNAM = opcode 0x43: FFNx's FieldOpcode enum lists "MESSAGE, MPARA,
  MPRA2, MPNAM" consecutively and MESSAGE = 0x40 is the mod's oldest
  live-proven table entry, so MPNAM = 0x43 by the same enum-counting rule
  that gave LINE/LINON/SLINE (v2.17, all three confirmed by disasm
  agreement). MPNAM takes one byte arg: a dialog-text index in the
  current field's text table — the handler either stores the INDEX to a
  global (menu resolves it later) or copies the TEXT somewhere static.
  Either way the written global is what the mod needs.

HOW (exe on disk, zero live interaction — same chain as v2.17):
  1. execute_opcode_table via grc(0x60BACF,0x80) → gav(^,0x10D); validate
     with the MESSAGE/ASK cross-checks before trusting anything.
  2. Disassemble table[0x43] (capstone), report every absolute global it
     writes. A one-byte-arg handler is tiny — expect a handful of
     instructions and ONE data write.
  3. Bonus context: disassemble neighbors MPARA (0x41) / MPRA2 (0x42) so
     a shared "menu parameter" block shows up as clustered writes.

Output feeds a live verify (read the discovered global while the game
shows a known location) before anything ships in the mod.
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
    f"mpnam_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- locate the exe on disk (same candidates as the v2.17 script) ----------------
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
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    sections.append((va, vs, rp))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp in sections:
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

# -- Step 1: opcode table + cross-checks (identical to v2.17) --------------------
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
print("ALL CROSS-CHECKS PASSED.\n")

# -- Step 2: disassemble MPNAM (+ neighbors for context) --------------------------
TARGETS = [
    (0x43, "MPNAM", "set map/location name shown in the main menu (1 byte arg)"),
    (0x41, "MPARA", "neighbor context"),
    (0x42, "MPRA2", "neighbor context"),
]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_handler(va, max_bytes=0x300):
    off = va_to_off(va)
    code = data[off:off + max_bytes]
    lines, writes, reads, indexed = [], {}, {}, []
    max_fwd = va
    end_va = va + max_bytes
    for insn in md.disasm(code, va):
        markers = []
        if insn.group(capstone.CS_GRP_JUMP) and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            tgt = insn.operands[0].imm
            if va < tgt < end_va:
                max_fwd = max(max_fwd, tgt)
        if insn.group(capstone.CS_GRP_CALL) and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            markers.append(f"CALL 0x{insn.operands[0].imm:08X}")
        for i, op in enumerate(insn.operands):
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            m = op.mem
            if m.base == 0 and m.index == 0 and m.disp > 0x400000:
                is_write = (i == 0 and insn.mnemonic.startswith(
                    ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                d = writes if is_write else reads
                d.setdefault(m.disp, []).append(insn.address)
                markers.append(f"{'W' if is_write else 'R'} GLOBAL[0x{m.disp:08X}]")
            elif m.base == 0 and m.index != 0 and m.disp > 0x400000:
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
    for a in sorted(writes):
        print(f"  WRITES GLOBAL 0x{a:08X}  at {', '.join('0x%X' % x for x in writes[a])}")
    for a in sorted(reads):
        print(f"  reads  global 0x{a:08X}  at {', '.join('0x%X' % x for x in reads[a])}")
    seen = set()
    for disp, scale, at in indexed:
        if (disp, scale) in seen:
            continue
        seen.add((disp, scale))
        print(f"  indexed array 0x{disp:08X} (scale {scale})")
    print()

# -- Step 3: follow MPNAM's storage callee ----------------------------------------
# The 0x43 handler is a thin arg-reader that CALLs one function with the
# text id — that callee performs the actual store the mod needs to find.
STORE_CALLEE = 0x633691
print(f"{'='*74}")
print(f"MPNAM storage callee 0x{STORE_CALLEE:08X}")
print(f"{'='*74}")
lines, writes, reads, indexed = disasm_handler(STORE_CALLEE, max_bytes=0x200)
for ln in lines:
    print(ln)
print(f"\n  -- callee summary --")
for a in sorted(writes):
    print(f"  WRITES GLOBAL 0x{a:08X}  at {', '.join('0x%X' % x for x in writes[a])}")
for a in sorted(reads):
    print(f"  reads  global 0x{a:08X}  at {', '.join('0x%X' % x for x in reads[a])}")
seen = set()
for disp, scale, at in indexed:
    if (disp, scale) in seen:
        continue
    seen.add((disp, scale))
    print(f"  indexed array 0x{disp:08X} (scale {scale})")
