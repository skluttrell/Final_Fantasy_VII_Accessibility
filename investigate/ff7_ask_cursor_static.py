#!/usr/bin/env python3
"""
ff7_ask_cursor_static.py -- Find the ASK choice menu's LIVE current-option
index (2026-07-19; player: choice menus only read the first option and
don't track the cursor).

FFNx (voice.cpp opcode_voice_ask) reads the current option as
*current_question_id, the 5th arg to field_opcode_ask_update_loop_6310A1.
So the ASK opcode handler passes a pointer to the selection variable.
Disassemble the ASK opcode handler (opcode table[0x48]) and the update
loop 0x6310A1 to find what global that pointer is (or how it's derived),
so the mod can read the highlighted option and announce it on change.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"ask_cursor_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

OPCODE_TABLE = 0x9055A0
def table_entry(op):
    return struct.unpack_from('<I', data, v2o(OPCODE_TABLE + op * 4))[0]

msg = table_entry(0x40)
assert data[v2o(msg + 0x3B)] == 0xE8, "opcode table validation FAILED"
print(f"opcode table OK (MESSAGE=0x{msg:X})\n")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def dump(label, start, length):
    print("=" * 70)
    print(f"{label}: 0x{start:X} (+0x{length:X})")
    print("=" * 70)
    off = v2o(start)
    if off is None:
        print("  (unmapped)"); return
    for insn in md.disasm(data[off:off + length], start):
        if insn.id == 0:
            continue
        marks = []
        for op in insn.operands:
            d = None
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
            elif op.type == capstone.x86.X86_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if 0x900000 <= v < 0xDE0000:
                    d = v
            if d is not None and 0x900000 <= d < 0xDE0000:
                marks.append(f"g_{d:X}")
        tgt = ""
        if insn.mnemonic == 'call':
            tgt = "   (call)"
        star = ("   ; " + ",".join(marks)) if marks else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}{tgt}")
        if insn.mnemonic == 'ret':
            break
    print()

ask_handler = table_entry(0x48)
print(f"opcode[0x48] ASK handler = 0x{ask_handler:X}")
dump("ASK opcode handler", ask_handler, 0x160)
# The update loop 6310A1 — its 5th arg is current_question_id (WORD*). Its
# body dereferences it; look for how the handler sets it up and any global.
dump("field_opcode_ask_update_loop_6310A1", 0x6310A1, 0x140)
