#!/usr/bin/env python3
"""
ff7_gateway_hit_disasm.py -- Final link in the arrival-facing proof chain
(2026-08-02, follow-up to ff7_gateway_cross_disasm.py).

WHAT IS ALREADY PROVEN (static, exe on disk):
  - MAPJUMP fills modules-global transition fields: +0x02 field, +0x04/+0x06
    X/Y, +0x22 triangle, +0x24 direction, +0x26 phase.
  - Field arrival code (0x63C073..0x63C094) applies +0x24 (0xCC0DAC) to the
    player's field_event_data +0x38 (rotation_curr_value) -- the same byte
    the DIR opcode writes and GETDIR reads.

REMAINING QUESTION:
  The WALK-ACROSS path: when the player crosses a gateway exit line, code at
  0x636245/0x63626E/0x63627D writes DEST_FIELD_ID/DEST_TRIANGLE/
  DEST_DIRECTION. Which gateway-record offsets feed them? Expected from the
  FFNx struct (24-byte record): +0x0C/+0x0E dest X/Y, +0x10 dest Z-or-
  triangle, +0x12 field id, +0x14..+0x17 the four "unknown" bytes -- the
  arrival direction should come from one of those four (community folklore
  says +0x14 with 3 pad/copy bytes; this listing decides it).

  Also disassemble 0x63CC80..0x63CD60 (second triangle+direction writer
  pair at 0x63CD07/0x63CD15) to identify that path (battle return? script
  PC restore?), so no writer is left unattributed.

Output teed to a timestamped log (standing investigation-script rule).
"""
import sys, os, struct, datetime, subprocess

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed.")
    sys.exit(1)

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"gateway_hit_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    sections.append((va, vs, rp, rs))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp, srs in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

KNOWN = {
    0xCFF454: "TRIGGERS_HDR_PTR",
    0xCBF9D8: "MODULES_PTR",
    0xCC0D8A: "DEST_FIELD_ID",
    0xCC0D8C: "DEST_X",
    0xCC0D8E: "DEST_Y",
    0xCC0DAA: "DEST_TRIANGLE",
    0xCC0DAC: "DEST_DIRECTION",
    0xCC0DAE: "JUMP_PHASE",
    0xCC0D89: "GAME_MODE",
    0xCC0964: "CURRENT_ENTITY",
    0xCC0B60: "EVENT_DATA_PTR",
    0xCC162C: "PLAYER_MODEL_ID",
    0xCC15D0: "FIELD_ID",
    0xCFF434: "WALKMESH_PTR",
    0xCFF744: "TRIANGLE_POOL_PTR",
    0xCFF748: "ACCESS_POOL_PTR",
    0xCC1F70: "FIELD_LINE_ARRAY",
}

def annotate(insn):
    notes = []
    for i, op in enumerate(insn.operands):
        if op.type == capstone.x86.X86_OP_MEM:
            m = op.mem
            if m.base == 0 and m.index == 0 and m.disp in KNOWN:
                is_write = (i == 0 and insn.mnemonic.startswith(
                    ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                notes.append(f"{'W' if is_write else 'R'} {KNOWN[m.disp]}")
            elif m.base == 0 and m.index == 0 and m.disp > 0x400000:
                notes.append(f"GLOBAL 0x{m.disp:08X}")
            elif m.base != 0 and 0 < m.disp < 0x300:
                is_write = (i == 0 and insn.mnemonic.startswith(
                    ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                notes.append(f"{'W' if is_write else 'R'} +0x{m.disp:X}({op.size}B)")
        elif op.type == capstone.x86.X86_OP_IMM and op.imm in KNOWN:
            notes.append(f"imm={KNOWN[op.imm]}")
    return notes

def disasm_region(lo, hi, title):
    print("=" * 74)
    print(f"REGION {title}: 0x{lo:08X}..0x{hi:08X}")
    print("=" * 74)
    va = lo
    while va < hi:
        off = va_to_off(va)
        if off is None:
            print(f"  0x{va:08X}  (unmapped)")
            return
        decoded = False
        for insn in md.disasm(data[off:off + (hi - va)], va):
            decoded = True
            notes = annotate(insn)
            print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}"
                  + (f"   ; {' | '.join(notes)}" if notes else ""))
            va = insn.address + insn.size
        if not decoded:
            print(f"  0x{va:08X}  db 0x{data[off]:02X}  (undecodable, +1)")
            va += 1
    print()

# The gateway-hit writer trio sits at 0x6362xx; start well before to catch
# the function head and the crossing test loop that precedes the stores.
disasm_region(0x635FA0, 0x6362E0, "gateway crossing test + hit path (walk-across transitions)")
# The second unattributed triangle+direction writer pair.
disasm_region(0x63CC80, 0x63CD60, "second DEST_TRIANGLE/DEST_DIRECTION writer (attribution)")

print("READ THE LISTING FOR: which [reg+0x14..0x17] (gateway record unknown")
print("bytes) or [reg+0x10] (dest z/triangle slot) feed DEST_TRIANGLE and")
print("DEST_DIRECTION on the hit path.")
print(f"\nLog saved to: {_log_path}")
