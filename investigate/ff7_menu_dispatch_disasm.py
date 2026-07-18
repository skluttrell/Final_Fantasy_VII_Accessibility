#!/usr/bin/env python3
"""
ff7_menu_dispatch_disasm.py -- One-off: disassemble the main-menu
sub-screen dispatcher (menu_sub_6CB56A, FFNx name-embedded VA) around the
menu_subs_call_table use (+0x2EC) to find the CURRENT-SUBMENU-ID global —
the value that indexes the table (item menu = index 3, established by
ff7_item_menu_static.py same day). The item-menu speaker thread will gate
on this global instead of guessing from cursor liveness.
"""
import sys, os, struct, datetime, subprocess

import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"menu_dispatch_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

def find_exe_path():
    for cand in (
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    ):
        if os.path.isfile(cand):
            return cand
    raise RuntimeError("ff7_en.exe not found")

with open(find_exe_path(), 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff_off = e_lfanew + 4
num_sections = struct.unpack_from('<HH', data, coff_off)[1]
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + 20 + opt_hdr_size - 20
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

FUNC = 0x6CB56A
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# Window: dispatch happens at +0x2EC (operand offset); disassemble a
# window before it so the index-register feed is visible.
start = FUNC + 0x2A0
code = data[va_to_off(start):va_to_off(start) + 0x90]
print(f"menu_sub_6CB56A dispatch window (0x{start:X}..):")
for insn in md.disasm(code, start):
    marker = ""
    if any(op.type == capstone.x86.X86_OP_MEM and
           (op.mem.disp & 0xFFFFFFFF) == 0x91AB98
           for op in insn.operands):
        marker = "   <== menu_subs_call_table use"
    print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{marker}")
