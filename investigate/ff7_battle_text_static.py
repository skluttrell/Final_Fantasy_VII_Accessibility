#!/usr/bin/env python3
"""
ff7_battle_text_static.py -- Two battle hunts (2026-07-19, player
reports: scorpion tail-up warning not spoken; some items/magic silent
or wrong in the battle lists):

HUNT 1 — battle DIALOG text (the "Attack while it's tail's up!"
  warning = scene AI message, a text channel the mod never spoke):
  - queue: battle_display_text_queue = battle_text_data[64] at
    gav(add_text_to_display_queue+0x25), where add_text_to_display_
    queue = grc(0x42CBF9 + 0x1C7) (FFNx chain, name-embedded anchor).
    Entry: short buffer_idx (-1 = empty), short field_2, byte
    wait_frames, byte n_frames (FFNx ff7.h).
  - text: FFNx's own voice code fetches it as get_kernel_text(8,
    buffer_idx, 8) — disassemble GET_KERNEL_TEXT's (0x41963C) section-8
    branch (jump table 0x419A38, the v2.10 section-7 method) to
    replicate the lookup without calling game code.

HUNT 2 — battle list-widget index formula: the v2.9 "index =
  w0+w4+scroll" was verified with a near-empty spell list where all
  formulas agree; with real materia the magic list (3 columns) now
  announces wrong entries. Disassemble BATTLE_MENU_FN_TABLE[5]/[6]
  (0x91E6B8) hunting the CONFIRM path's entry-index computation (the
  *6 access into the char-block magic list / global item table).
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_text_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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
def grc(addr, offset):
    off = v2o(addr + offset)
    if off is None or data[off] != 0xE8:
        return None
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return addr + offset + 5 + rel
def gav(addr, offset):
    return struct.unpack_from('<I', data, v2o(addr + offset))[0]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def dump(label, start, length, stop_at_ret=True):
    print("=" * 70)
    print(f"{label}: 0x{start:X} (+0x{length:X})")
    print("=" * 70)
    off = v2o(start)
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
        star = ("   ; " + ",".join(marks)) if marks else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}")
        if stop_at_ret and insn.mnemonic == 'ret':
            break
    print()

# ── HUNT 1a: the text queue base ─────────────────────────────────────
addq = grc(0x42CBF9, 0x1C7)
print(f"add_text_to_display_queue = 0x{addq:X}")
queue_base = gav(addq, 0x25)
print(f"battle_display_text_queue = 0x{queue_base:X} (battle_text_data[64], "
      f"entry: s16 buffer_idx @+0, -1 = empty)\n")
dump("add_text_to_display_queue", addq, 0x120)

# ── HUNT 1b: get_kernel_text section-8 branch ───────────────────────
# 0x41963C's battle-section switch: jump table 0x419A38 indexed by
# section (v2.10's derivation). Dump table entry 8's handler.
jt8 = struct.unpack_from('<I', data, v2o(0x419A38 + 8 * 4))[0]
print(f"get_kernel_text jump table[8] (battle text section) = 0x{jt8:X}")
dump("section-8 handler", jt8, 0x180, stop_at_ret=False)

# ── HUNT 2: battle-menu state handlers 5 (item) and 6 (magic) ───────
for st in (5, 6):
    h = struct.unpack_from('<I', data, v2o(0x91E6B8 + st * 4))[0]
    print(f"BATTLE_MENU_FN_TABLE[{st}] = 0x{h:X}")
    dump(f"state-{st} handler (hunt the *6 index computation)", h, 0x600,
         stop_at_ret=False)
