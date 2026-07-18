#!/usr/bin/env python3
"""
ff7_timer_static.py -- Statically locate the field COUNTDOWN TIMER state
(2026-07-18; user request: timed-escape announcements + freeze, T /
Shift+T per accessiblity_keys.txt).

WHY STATIC FIRST: the first timer in the game starts after the one-shot
scorpion boss — the plan is to ship a speculative, debug-logging,
self-calibrating announcer BEFORE that fight, so the player's natural
escape run doubles as the live verify. Everything checkable without the
game running gets checked here.

LEADS (all prior-find anchored):
  1. FFNx savemap struct names uint32 `countdown_timer` at +0xB84
     (0xDC08BC) — right after gil (+0xB7C) and play-seconds (+0xB80).
  2. STTIM = field opcode 0x38 (FFNx FieldOpcode enum counted to the
     MESSAGE=0x40 anchor — the LINE/MPNAM rule). Its handler writes the
     timer start value somewhere; args are h,m,s bytes per community doc.
  3. WSPCL (0x36) creates the special clock window, WNUMB (0x37) its
     numeric value — their handlers show the display-side state.
  4. FFNx: timer_menu_sub = menu_subs_call_table[0] (= 0x6CA346, the
     main-menu screen sub we disassembled for v2.32) and
     millisecond_counter = dword operand at +0xD06 — the countdown
     draw/decrement code lives in that sub.

METHOD: opcode table 0x9055A0 from the exe on disk (v2.17's chain,
validated by MESSAGE+0x3B=E8 before use); linear disasm of the three
handlers + the timer region of table[0]; annotate every absolute
0x9xxxxx/0xDxxxxx data ref, flagging savemap+0xB84 and known symbols.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"timer_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
_log = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s)
    _log.write(s)
    _log.flush()
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

# Validate the table exactly as v2.17 did: MESSAGE (0x40) handler must
# have an E8 CALL at +0x3B.
msg = table_entry(0x40)
assert data[v2o(msg + 0x3B)] == 0xE8, "opcode table validation FAILED"
print(f"opcode table OK (MESSAGE=0x{msg:X}, +0x3B=E8)\n")

KNOWN = {
    0xDC08BC: "SAVEMAP+0xB84 countdown_timer(FFNx)",
    0xDC08B4: "savemap+0xB7C gil",
    0xDC08B8: "savemap+0xB80 play_seconds",
    0xDC1154: "MENU_CURSOR", 0xDC12DC: "MENU_OPEN",
    0xDC1138: "menu frame ctr", 0xDC1210: "frame parity",
    0xCC0CF8: "field_curr_script_position", 0xCC0964: "current_entity_id",
}

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def dump(label, start, length):
    print("=" * 70)
    print(f"{label}: 0x{start:X} (+0x{length:X})")
    print("=" * 70)
    off = v2o(start)
    if off is None:
        print("  (not mapped)")
        return
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
            if d is not None and (0x900000 <= d < 0xDE0000):
                marks.append(KNOWN.get(d, f"g_{d:X}"))
        star = ("   ; " + ",".join(marks)) if marks else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}")
        if insn.mnemonic == 'ret':
            break
    print()

for op, name in ((0x36, "WSPCL (create clock window)"),
                 (0x37, "WNUMB (window numeric value)"),
                 (0x38, "STTIM (set timer h,m,s)")):
    ev = table_entry(op)
    print(f"opcode 0x{op:02X} {name}: handler = 0x{ev:X}")
for op, name in ((0x36, "WSPCL"), (0x37, "WNUMB"), (0x38, "STTIM")):
    dump(f"{name} handler", table_entry(op), 0x200)

# Timer draw/decrement region of the menu timer sub (FFNx: table[0] =
# timer_menu_sub; millisecond_counter operand at +0xD06). Window around it.
TIMER_SUB = 0x6CA346
print(f"FFNx millisecond_counter operand @ timer_sub+0xD06 -> "
      f"0x{struct.unpack_from('<I', data, v2o(TIMER_SUB + 0xD06))[0]:X}")
dump("timer_menu_sub timer region (+0xB80..+0xF80)", TIMER_SUB + 0xB80, 0x400)
