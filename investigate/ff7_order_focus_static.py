#!/usr/bin/env python3
"""
ff7_order_focus_static.py -- Find the main menu's "focus is in the party
pane" state (the Order screen's missing entry signal, 2026-07-18).

WHY: the Order "screen" is no screen at all — the dispatcher index stays
0 (order_menu_scan_20260718_152825) and the player hears no chime; the
main-menu screen just moves input focus into the party pane. The A/B/A
entry probe (order_entry_probe_20260718_153813) found NOTHING in BSS
that toggles on entry — the focus state is evidently behind a pointer
(heap widget structs — the exact battle-menu-cursor situation, where the
cursor hid behind a struct pointer invisible to absolute scans).

METHOD (the battle-menu trick in reverse): we KNOW two Order-pane
globals from the guided scan — the party cursor 0xDC11C4 and the
selection latch 0xDC1320. The code that WRITES them only runs while
focus is in the pane, so:
  1. sweep the main-menu screen sub (menu_subs_call_table[0] = 0x6CA346,
     table @0x91AB98 — ff7_item_menu_static.py provenance) plus callees;
  2. locate every instruction writing 0xDC11C4 / 0xDC1320 and reading
     MENU_CURSOR 0xDC1154;
  3. print disasm windows around them — the guarding conditionals just
     before/around those writes read the focus variable (global or
     [ptr+off] chain), and cmp-immediates against MENU_CURSOR==5 mark
     the Order row dispatch.
Output is for eyeballing; whatever global the guards read gets a live
sanity check before shipping.
"""
import sys, os, struct, datetime
from collections import defaultdict

import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"order_focus_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore)
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

TABLE_VA   = 0x91AB98
MAIN_MENU  = struct.unpack_from('<I', data, va_to_off(TABLE_VA))[0]  # table[0]
print(f"menu_subs_call_table[0] (main menu screen sub) = 0x{MAIN_MENU:08X}")

TARGETS = {
    0xDC11C4: "ORDER_PARTY_CURSOR",
    0xDC1320: "ORDER_SELECT_LATCH",
}
MENU_CURSOR = 0xDC1154

MENU_MOD_LO, MENU_MOD_HI = 0x6C0000, 0x720000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

# BFS the main-menu sub to depth 3, remembering each function's VA so hit
# windows can be disassembled again for printing.
FUNC_WINDOW = 0x2000
seen, frontier = set(), [MAIN_MENU]
hits = []          # (function_va, insn_va, kind, text)
for depth in range(3):
    nxt = []
    for fva in frontier:
        if fva in seen or len(seen) > 300:
            continue
        seen.add(fva)
        foff = va_to_off(fva)
        if foff is None:
            continue
        for insn in md.disasm(data[foff:foff + FUNC_WINDOW], fva):
            if insn.id == 0:
                continue
            if insn.mnemonic == 'call':
                try:
                    tgt = int(insn.op_str, 16)
                    if MENU_MOD_LO <= tgt < MENU_MOD_HI:
                        nxt.append(tgt)
                except ValueError:
                    pass
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    disp = op.mem.disp & 0xFFFFFFFF
                    if disp in TARGETS:
                        kind = TARGETS[disp] + (
                            " WRITE" if op.access & capstone.CS_AC_WRITE else " read")
                        hits.append((fva, insn.address, kind,
                                     f"{insn.mnemonic} {insn.op_str}"))
                    elif disp == MENU_CURSOR:
                        hits.append((fva, insn.address, "MENU_CURSOR ref",
                                     f"{insn.mnemonic} {insn.op_str}"))
    frontier = nxt

print(f"\nswept {len(seen)} functions; {len(hits)} target references\n")

# Print a disasm window around each hit (dedup by window).
printed = set()
for fva, iva, kind, text in sorted(hits, key=lambda h: h[1]):
    wstart = iva - 0x60
    key = wstart & ~0xF
    print(f"--- {kind} @0x{iva:X} ({text})  [in sweep of 0x{fva:X}] ---")
    if key in printed:
        print("    (window overlaps one printed above)\n")
        continue
    printed.add(key)
    woff = va_to_off(wstart)
    if woff is None:
        continue
    for insn in md.disasm(data[woff:woff + 0xC0], wstart):
        if insn.id == 0:
            continue
        marks = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
                if d in TARGETS:
                    marks.append(TARGETS[d])
                elif d == MENU_CURSOR:
                    marks.append("MENU_CURSOR")
        star = ("   <== " + ",".join(marks)) if marks else ""
        cur = " <<<<" if insn.address == iva else ""
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{star}{cur}")
    print()
