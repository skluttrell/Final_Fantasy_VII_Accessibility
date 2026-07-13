#!/usr/bin/env python3
"""
ff7_battle_menu_submenu_disasm.py -- Full listings of the battle SUB-MENU
state handlers (magic/summon/item lists) + the shared widget-navigation
helper, to locate the list cursor fields.

CONTEXT (2026-07-12, follows ff7_battle_menu_handler_disasm.py)
---------------------------------------------------------------
The command-menu cursor is now statically solved (state-1 handler
0x6D91FA):

    slot   = u8 [0xDC3C7C]                     (active actor party slot)
    widget = 0xDC20A0 + slot*0x700             (per-actor menu widget block)
    row    = u32 [widget+0]   wraps mod u8[0xDBA4B9 + slot*0x440]
    col    = u32 [widget+4]   wraps mod 4
    entry  = 0xDBA4E4 + slot*0x440 + (row*4+col)*6
             u8[entry+0] = command id (0xFF = empty, nav skips it)
             u8[entry+1] = action type (0..0xB jump table on Confirm)
             u8[entry+2] -> word 0xDC3C84 on some paths (action id?)

    Confirm writes: entry[0] -> 0xDC3C70 (= FFNx issued_command_id),
    entry[1] -> 0xDC3C74, input word 0x9A889A snapshot -> 0xDC3C60,
    then battle_menu_state (0x91EF9C) transitions: 5 = magic list,
    6 = one list, 7 = another list, 4/0x14/0x18/0x1A/0x1B = misc
    (coin/ESkill/limit-ish; to be pinned down).

WHAT THIS SCRIPT ANSWERS
------------------------
Where are the MAGIC / SUMMON / ITEM list cursors (row + scroll offset)?
The state 5/6/7 handlers (0x6D98E3 / 0x6D9B98 / 0x6DA072) must read and
write them, and the shared navigation helper 0x6F4DB2 (called by 9 of
the handlers with a widget pointer argument) contains the actual
increment/decrement/wrap logic -- its [reg+disp] field offsets ARE the
widget struct layout. We dump full listings of all four plus the
smaller shared helpers:

    0x6F53F1  (8 insns, called by 13 handlers -- input-check thunk?)
    0x74580A  (35 insns, called by 13 handlers -- cursor SFX player?)
    0x437679  (121 insns -- called with (slot, 0) at state-1 entry)

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_battle_menu_submenu_disasm.py
"""
import sys, os, struct, datetime

import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_menu_submenu_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee

IMAGE_BASE = 0x400000

# (entry VA, why we care)
TARGETS = [
    (0x6D98E3, "state 5 handler -- magic list (Confirm on Magic goes here)"),
    (0x6D9B98, "state 6 handler -- list opened by action-type 2 (item?)"),
    (0x6DA072, "state 7 handler -- list opened by action-type 4"),
    (0x6F4DB2, "shared widget navigation helper (input -> cursor movement)"),
    (0x6F53F1, "tiny shared helper -- input check thunk?"),
    (0x74580A, "shared helper -- cursor sound player?"),
    (0x437679, "called at state-1 entry with (slot, 0)"),
]

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\Final Fantasy VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\Final Fantasy VII Steam Edition\ff7\resources\ff7_1.02\ff7_en",
]

def parse_pe_sections(data):
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    oph = struct.unpack_from('<H', data, pe + 20)[0]
    off = pe + 24 + oph
    out = []
    for i in range(nsec):
        s = off + i * 40
        va   = struct.unpack_from('<I', data, s + 12)[0]
        vsz  = struct.unpack_from('<I', data, s + 8)[0]
        roff = struct.unpack_from('<I', data, s + 20)[0]
        rsz  = struct.unpack_from('<I', data, s + 16)[0]
        out.append((va, max(vsz, rsz), roff))
    return out

_SECTIONS = None
def va_to_off(data, va):
    global _SECTIONS
    if _SECTIONS is None:
        _SECTIONS = parse_pe_sections(data)
    rva = va - IMAGE_BASE
    for va0, span, roff in _SECTIONS:
        if va0 <= rva < va0 + span:
            return roff + (rva - va0)
    return None

def read_bytes(data, va, n):
    off = va_to_off(data, va)
    if off is None or off + n > len(data):
        return None
    return data[off:off + n]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_function(data, entry, max_len=0x3000):
    raw = read_bytes(data, entry, max_len)
    if raw is None:
        return []
    insns = []
    max_target = entry
    for insn in md.disasm(raw, entry):
        insns.append(insn)
        if insn.group(capstone.CS_GRP_JUMP):
            for op in insn.operands:
                if op.type == capstone.CS_OP_IMM and \
                   entry < op.imm < entry + max_len:
                    max_target = max(max_target, op.imm)
        if insn.mnemonic == 'ret' and insn.address >= max_target:
            break
        if insn.mnemonic == 'int3':
            break
    return insns

def main():
    print(f"Log: {_log_path}")
    data = None
    for p in EXE_CANDIDATES:
        if os.path.exists(p):
            data = open(p, 'rb').read()
            print(f"Loaded exe: {p}")
            break
    if data is None:
        print("ERROR: exe not found")
        return 1

    for va, why in TARGETS:
        insns = disasm_function(data, va)
        print()
        print("=" * 72)
        print(f"===== {va:#010x}  ({len(insns)} insns)  {why}")
        print("=" * 72)
        for insn in insns:
            print(f"  {insn.address:#010x}  {insn.mnemonic:<8s} {insn.op_str}")

    print()
    print(f"Log saved to: {_log_path}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
