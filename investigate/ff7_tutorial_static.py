#!/usr/bin/env python3
"""
ff7_tutorial_static.py -- Map the menu module's TUTORIAL interpreter
(2026-07-26; play report on v2.30.27: whole lesson read up front, then
silence while the player guesses the advance key per slide).

WHAT THE FIX NEEDS (per-slide narration + "press X to continue"):
  1. The LIVE current-window state -- FFNx already names it:
       menu_tutorial_sub_6C49FD        = get_relative_call(0x6CB56A, 0x2B7)
       menu_tutorial_window_state BYTE* = get_absolute_value(6C49FD, 0x9)
       menu_tutorial_window_text_ptr    = get_absolute_value(6C49FD, 0x18)
     FFNx's voice.cpp polls the state byte per frame: 0->1 = window
     opening, 1->2 = text started (text_ptr now points at the CURRENT
     slide's text), 3->0 = closing. That is exactly the per-slide sync
     signal v2.30.27 said was "unmapped".
  2. The interpreter's script-position global + per-opcode semantics --
     which opcodes WAIT for player input (and which input: the user
     reports directions sometimes, buttons other times), which just
     time out. Source: full disasm of 6C49FD (this script), which is
     called once per menu tick from the main-menu dispatcher, so it
     must keep its position/wait state in globals between calls.

OUTPUT: resolved global addresses + the full annotated interpreter
disasm for hand-reading opcode cases.
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
    f"tutorial_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def get_relative_call(addr, offset):
    off = va_to_off(addr + offset)
    assert off is not None
    assert data[off] == 0xE8, (
        f"byte at 0x{addr+offset:X} is 0x{data[off]:02X}, not E8 -- chain broke")
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return (addr + offset + 5 + rel) & 0xFFFFFFFF

def gav(addr, offset):
    off = va_to_off(addr + offset)
    return struct.unpack_from('<I', data, off)[0] if off is not None else None

# -- resolve the FFNx chain ------------------------------------------------------
MENU_DISPATCH = 0x6CB56A            # name-embedded, long-proven anchor
tut = get_relative_call(MENU_DISPATCH, 0x2B7)
print(f"menu_sub_6CB56A+0x2B7 -> tutorial interpreter 0x{tut:X}")
assert tut == 0x6C49FD, f"expected FFNx's 0x6C49FD, got 0x{tut:X} -- STOP"
state_byte = gav(tut, 0x9)
text_ptr   = gav(tut, 0x18)
print(f"  menu_tutorial_window_state    = 0x{state_byte:X} (BYTE)")
print(f"  menu_tutorial_window_text_ptr = 0x{text_ptr:X} (DWORD -> text)")
print()

# -- full annotated disasm of the interpreter ------------------------------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def dump(fva, length, title):
    print(f"===== {title} @ 0x{fva:X} (len 0x{length:X}) =====")
    foff = va_to_off(fva)
    code = data[foff:foff + length]
    for insn in md.disasm(code, fva):
        if insn.id == 0:
            print(f"  0x{insn.address:X}: .byte {insn.bytes.hex()}")
            continue
        notes = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
                if d == state_byte: notes.append("WINDOW_STATE")
                if d == text_ptr:   notes.append("TEXT_PTR")
        line = f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}"
        if notes:
            line += "   ; " + " ".join(notes)
        print(line)
    print()

# The interpreter: dump generously -- it holds the opcode switch. Also dump
# a window around it in case helpers sit adjacent.
dump(tut, 0xE00, "menu_tutorial interpreter (6C49FD)")
