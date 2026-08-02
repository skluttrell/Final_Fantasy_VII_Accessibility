#!/usr/bin/env python3
"""
ff7_mpjpo_static.py -- Confirm what the MPJPO opcode (0xD2, "map jump port
on/off") actually writes (2026-08-02, the last open engine question before
the transition-tracking feature ships).

WHY:
  The transition tracker will guide players toward gateway exit lines. But
  field scripts can disable gateway jumps wholesale (cutscenes do this) --
  the PSX decomp names modules_global_object +0x36 "map jump disabled"
  (0xCC0DBE in our static block, research doc §14 sub-map). If MPJPO's
  handler writes that byte, the mod can read it and avoid guiding a player
  onto a dead exit during a scene. One handler disasm settles it -- the
  exact recipe that decoded DIR/MAPJUMP/LINE (resolve execute_opcode_table
  from the exe on disk, then capstone the handler).

EXPECTED SHAPE (from every other one-arg field opcode read to date):
  read CURRENT_ENTITY 0xCC0964 -> script PC array 0xCC0CF8 -> operand byte
  via SCRIPT_PTR 0xCBF5E8 -> store somewhere -> PC += 2. The "somewhere" is
  the answer: [0xCBF9D8]+0x36 (= static 0xCC0DBE) proves the PSX label.

Output teed to a timestamped log (standing investigation-script rule).
"""
import sys, os, struct, datetime

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed.")
    sys.exit(1)

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"mpjpo_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
data = open(exe_path, 'rb').read()

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
execute_opcode = grc(0x60BACF, 0x80)
table_va = gav(execute_opcode, 0x10D)
table_off = va_to_off(table_va)
entries = struct.unpack_from('<256I', data, table_off)
msg = entries[0x40]
assert CODE_LO <= msg <= CODE_HI and data[va_to_off(msg + 0x3B)] == 0xE8, \
    "MESSAGE cross-check failed -- do not trust the table"
print(f"execute_opcode_table = 0x{table_va:08X}  (MESSAGE cross-check OK)\n")

KNOWN = {
    0xCBF9D8: "MODULES_PTR(->0xCC0D88)",
    0xCC0964: "CURRENT_ENTITY",
    0xCC0CF8: "SCRIPT_PC[]",
    0xCBF5E8: "SCRIPT_PTR",
    0xCC0DBE: "static modules+0x36 'map jump disabled'",
}

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

va = entries[0xD2]
print(f"table[0xD2] MPJPO = 0x{va:08X}")
print("=" * 74)
off = va_to_off(va)
struct_writes = {}
for insn in md.disasm(data[off:off + 0x200], va):
    notes = []
    for i, op in enumerate(insn.operands):
        if op.type == capstone.x86.X86_OP_MEM:
            m = op.mem
            is_write = (i == 0 and insn.mnemonic.startswith(
                ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
            if m.base == 0 and m.index == 0 and m.disp in KNOWN:
                notes.append(f"{'W' if is_write else 'R'} {KNOWN[m.disp]}")
            elif m.base == 0 and m.index == 0 and m.disp > 0x400000:
                notes.append(f"{'W' if is_write else 'R'} GLOBAL 0x{m.disp:08X}")
            elif m.base != 0 and 0 < m.disp < 0x300:
                if is_write:
                    struct_writes.setdefault(m.disp, []).append(insn.address)
                notes.append(f"{'W' if is_write else 'R'} +0x{m.disp:X}({op.size}B)")
    print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}"
          + (f"   ; {' | '.join(notes)}" if notes else ""))
    if insn.mnemonic.startswith('ret'):
        break

print("\nSUMMARY: pointer-relative writes:",
      {f'+0x{d:X}': [f'0x{a:X}' for a in v] for d, v in struct_writes.items()})
print("If the write is [MODULES_PTR]+0x36 (or absolute 0xCC0DBE), the PSX")
print("'map jump disabled' label is CONFIRMED: MPJPO arg -> that byte,")
print("nonzero = gateways dead. The tracker reads it before guiding to exits.")
print(f"\nLog saved to: {_log_path}")
