#!/usr/bin/env python3
"""
ff7_order_block_disasm.py -- One-off: linear disasm of the main-menu
sub's Order block (0x6CA4C0-0x6CA8D0) to find the guard that routes
execution into it — the "focus is in the party pane" condition the
entry probe couldn't see in BSS. Companion to ff7_order_focus_static.py
(2026-07-18); marks every absolute BSS memory operand so the mode/focus
variable stands out.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"order_block_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s)
    _log_file.write(s)
    _log_file.flush()
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

KNOWN = {
    0xDC1154: "MENU_CURSOR", 0xDC11C4: "ORDER_CURSOR", 0xDC1320: "LATCH",
    0xDC12DC: "MENU_OPEN", 0xDC12EC: "DISPATCH_IDX", 0xDC12E8: "DISPATCH_TRN",
    0xDC0230: "PARTY_IDS", 0xDC1259: "MYSTERY_1259", 0xDC1210: "FRAME_PARITY",
    0xDC1138: "FRAME_CTR",
}

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True
START, END = 0x6CA4C0, 0x6CA8D0
print(f"Linear disasm 0x{START:X}..0x{END:X} (main-menu sub Order block):\n")
for insn in md.disasm(data[v2o(START):v2o(END)], START):
    if insn.id == 0:
        continue
    marks = []
    for op in insn.operands:
        if op.type == capstone.x86.X86_OP_MEM:
            d = op.mem.disp & 0xFFFFFFFF
            if d in KNOWN:
                marks.append(KNOWN[d])
            elif 0xDB0000 <= d < 0xDE0000:
                marks.append(f"g_{d:X}")
    star = ("   ; " + ",".join(marks)) if marks else ""
    print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}")
