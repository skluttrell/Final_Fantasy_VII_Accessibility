#!/usr/bin/env python3
"""
ff7_ask_lines_static.py -- Find whether the ASK opcode carries first_line/
last_line parameters beyond window_id/dialog_id, and how
field_opcode_ask_update_loop_6310A1 uses them (2026-07-20; player report:
per-option TTS announces the right TEXT but at the WRONG cursor position --
"only one will speak and it is the first choice but... at the end of the
choice set instead of the beginning" -- exactly the symptom of the mod's
FF7Text::DecodeLines() line index not matching the game's own option
index, e.g. because DecodeLines counts a leading question line that the
game's cursor numbering does not).

ff7_ask_cursor_static_20260719_150732.log already found the ASK opcode
handler (0x618E83) pushes FOUR raw script bytes (offsets +2,+3,+4,+5 from
the opcode) into field_opcode_ask_update_loop_6310A1 -- we only know
+2=window_id, +3=dialog_id (matching the mod's existing param reads).
+4 and +5 were never inspected: that log's dump() call was capped at
0x140 bytes and cut off before the update loop's case bodies used them
(if they do). This script dumps MUCH further into 6310A1 and flags every
instruction touching [ebp+0x10] (+4 byte) or [ebp+0x14] (+5 byte).
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"ask_lines_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
_log = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s); _log.write(s); _log.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

def find_exe():
    for cand in (
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    ):
        if os.path.isfile(cand):
            return cand
    raise RuntimeError("exe not found")

with open(find_exe(), 'rb') as f:
    data = f.read()
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff = e_lfanew + 4
nsec = struct.unpack_from('<HH', data, coff)[1]
optsz = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
base = struct.unpack_from('<I', data, opt + 28)[0]
secoff = opt + optsz
secs = []
for i in range(nsec):
    o = secoff + i * 40
    vs, va, rs, rp = struct.unpack_from('<IIII', data, o + 8)
    secs.append((va, vs, rp))
def v2o(va):
    r = va - base
    for sva, svs, srp in secs:
        if sva <= r < sva + svs:
            return srp + (r - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def dump_full(label, start, max_length):
    """Disassemble from `start` until a top-level `ret` (ebp/esp restored),
    or max_length bytes, whichever comes first. Flags [ebp+0x10]/[ebp+0x14]."""
    print("=" * 70)
    print(f"{label}: 0x{start:X}")
    print("=" * 70)
    off = v2o(start)
    if off is None:
        print("  (unmapped)"); return
    hits = []
    for insn in md.disasm(data[off:off + max_length], start):
        if insn.id == 0:
            continue
        flag = ""
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base != 0:
                base_reg = insn.reg_name(op.mem.base)
                if base_reg == 'ebp' and op.mem.disp == 0x10:
                    flag = "   <-- [ebp+0x10] (opcode byte +4)"
                elif base_reg == 'ebp' and op.mem.disp == 0x14:
                    flag = "   <-- [ebp+0x14] (opcode byte +5)"
        if flag:
            hits.append((insn.address, insn.mnemonic, insn.op_str))
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{flag}")
        if insn.mnemonic == 'ret':
            break
    print()
    print(f"-- {len(hits)} instruction(s) touching +4/+5 --")
    for addr, mn, ops in hits:
        print(f"   0x{addr:X}: {mn} {ops}")
    print()

dump_full("field_opcode_ask_update_loop_6310A1 (full)", 0x6310A1, 0x800)

print(f"\nLog: {_log_path}")
