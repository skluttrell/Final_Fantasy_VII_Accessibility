#!/usr/bin/env python3
"""
ff7_battle_menu_handler_disasm.py -- Deep disassembly of the battle menu
state handlers + the battle menu DRAW function, to locate the command
cursor variable(s).

CONTEXT (follows ff7_battle_menu_static.py, same session 2026-07-12)
--------------------------------------------------------------------
The static pass proved the FFNx chain resolves cleanly on our exe and
dumped all 64 state handlers. Key facts it established:

  - battle_menu_state (current widget selector) = WORD at 0x91EF9C.
  - NO handler mutates a small absolute-address global by +-1. So the
    cursor is NOT navigated via a direct `inc [imm32]` in the handlers.
    Either (a) navigation happens in a SHARED HELPER the handlers call,
    or (b) it operates on a widget STRUCT through a register pointer
    ([reg+disp] operands were invisible to the absolute-only extractor),
    or both -- which is exactly the PSX menu-widget architecture.
  - Many states have 4-instruction stub handlers (e.g. 0x6D8C5C serves
    13 states) -- these presumably tail-call or flag into shared code.
  - State 1's handler 0x6D91FA is the largest (390 insns) and reads the
    input word 0x9A889A: prime suspect for command-menu navigation.

TWO NEW ANGLES THIS SCRIPT TAKES
--------------------------------
  1. CALLEE ANALYSIS: disassemble every function CALLed by the state
     handlers (one level deep) and apply the same global-extraction +
     +-1-mutation detection there. A shared "move cursor in list widget"
     helper would light up with +-1 ops on either a global or [reg+disp].
  2. THE DRAW SIDE: display_battle_menu_6D797C must READ the cursor
     position every frame to draw the hand pointer next to the selected
     command. Whatever small global (or struct field) it reads that the
     state handlers WRITE is the cursor. We disassemble it and its
     callees too, then intersect.

Also prints FULL annotated listings for the handful of functions that
matter most (state 0, state 1, one stub) so the widget-struct addressing
pattern can be read by eye in the log.

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_battle_menu_handler_disasm.py
"""
import sys, os, struct, datetime
from collections import defaultdict

import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_menu_handler_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee

IMAGE_BASE = 0x400000
DATA_LO, DATA_HI = 0x900000, 0xE00000

# Resolved by ff7_battle_menu_static.py (battle_menu_static_20260712_211141.log)
FN_TABLE          = 0x91E6B8
BATTLE_MENU_STATE = 0x91EF9C
DISPLAY_MENU      = 0x6D797C

# Full-listing targets: state 0 (actor ready), state 1 (big nav suspect),
# state 2 (medium), the 13-state stub, and one of the 32-39 stubs.
FULL_LISTING = [0x6D8C75, 0x6D91FA, 0x6D9DBE, 0x6D8C5C, 0x6D8F1D]

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

def read_u32(data, va):
    b = read_bytes(data, va, 4)
    return struct.unpack('<I', b)[0] if b else None

def in_code(va):  return va is not None and 0x401000 <= va <= 0x9FFFFF
def in_data(va):  return va is not None and DATA_LO <= va < DATA_HI

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_function(data, entry, max_len=0x2000):
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

def call_targets(insns):
    out = []
    for insn in insns:
        if insn.mnemonic == 'call':
            op = insn.operands[0]
            if op.type == capstone.CS_OP_IMM and in_code(op.imm):
                out.append(op.imm)
    return out

def jump_out_targets(insns, entry, span=0x2000):
    """Tail-call detection: unconditional jmps that leave the function body."""
    out = []
    for insn in insns:
        if insn.mnemonic == 'jmp':
            op = insn.operands[0]
            if op.type == capstone.CS_OP_IMM and in_code(op.imm) and \
               not (entry <= op.imm < entry + span):
                out.append(op.imm)
    return out

def analyze(insns):
    """Return (abs_globals, pm1_abs, pm1_reg) where:
       abs_globals: {addr: descriptors} for absolute data operands
       pm1_abs:     set of absolute addrs mutated by exactly +-1
       pm1_reg:     list of (insn_str) for +-1 mutations on [reg+disp]"""
    abs_globals = defaultdict(set)
    pm1_abs, pm1_reg = set(), []
    for insn in insns:
        pm1 = insn.mnemonic in ('inc', 'dec') or (
            insn.mnemonic in ('add', 'sub') and len(insn.operands) == 2
            and insn.operands[1].type == capstone.CS_OP_IMM
            and abs(insn.operands[1].imm) == 1)
        for op in insn.operands:
            if op.type != capstone.CS_OP_MEM:
                continue
            m = op.mem
            if m.base == 0 and m.index == 0:
                addr = m.disp & 0xFFFFFFFF
                if in_data(addr):
                    rw = 'w' if (op.access & capstone.CS_AC_WRITE) else 'r'
                    abs_globals[addr].add(f"{insn.mnemonic}/{op.size}B/{rw}")
                    if pm1 and (op.access & capstone.CS_AC_WRITE):
                        pm1_abs.add(addr)
            elif pm1 and (op.access & capstone.CS_AC_WRITE):
                pm1_reg.append(f"{insn.address:#010x}  {insn.mnemonic} {insn.op_str}")
    return abs_globals, pm1_abs, pm1_reg

def main():
    print(f"Log: {_log_path}")
    print("=" * 72)
    data = None
    for p in EXE_CANDIDATES:
        if os.path.exists(p):
            data = open(p, 'rb').read()
            print(f"Loaded exe: {p}")
            break
    if data is None:
        print("ERROR: exe not found")
        return 1

    entries = [read_u32(data, FN_TABLE + i * 4) for i in range(64)]
    uniq_handlers = sorted({e for e in entries if in_code(e)})

    # ---------- Pass 1: handlers + collect callees ---------------------
    print()
    print("--- Pass 1: state handlers, call graph ----------------------------")
    callees = {}           # callee addr -> set of caller handler addrs
    handler_insns = {}
    for h in uniq_handlers:
        insns = disasm_function(data, h)
        handler_insns[h] = insns
        states = [i for i, x in enumerate(entries) if x == h]
        calls = call_targets(insns)
        tails = jump_out_targets(insns, h)
        print(f"handler {h:#010x} states={states}: "
              f"{len(insns)} insns, calls={[hex(c) for c in calls]}"
              + (f", tail-jmps={[hex(t) for t in tails]}" if tails else ""))
        for c in calls + tails:
            callees.setdefault(c, set()).add(h)

    # ---------- Pass 2: callee analysis --------------------------------
    print()
    print("--- Pass 2: one-level callee analysis ------------------------------")
    print("(hunting the shared list-navigation helper: +-1 mutations)")
    shared_write_globals = defaultdict(set)   # addr -> writer fn set
    for c in sorted(callees):
        insns = disasm_function(data, c)
        abs_g, pm1_abs, pm1_reg = analyze(insns)
        ncallers = len(callees[c])
        interesting = pm1_abs or pm1_reg
        # print every callee once, verbose only when interesting
        line = (f"callee {c:#010x} ({len(insns)} insns, "
                f"{ncallers} caller handler(s))")
        if not interesting:
            print(line)
        else:
            print(line + "  <<< HAS +-1 MUTATIONS")
            for a in sorted(pm1_abs):
                print(f"    +-1 on GLOBAL {a:#010x}  "
                      f"[{', '.join(sorted(abs_g[a]))}]")
            for s in pm1_reg[:20]:
                print(f"    +-1 on struct field: {s}")
        for a, descs in abs_g.items():
            if any(d.endswith('/w') for d in descs):
                shared_write_globals[a].add(c)

    # ---------- Pass 3: the draw side -----------------------------------
    print()
    print("--- Pass 3: display_battle_menu 0x6D797C reads --------------------")
    draw_insns = disasm_function(data, DISPLAY_MENU, max_len=0x4000)
    draw_abs, _, _ = analyze(draw_insns)
    draw_calls = call_targets(draw_insns)
    print(f"display_battle_menu: {len(draw_insns)} insns, "
          f"{len(draw_calls)} calls, {len(draw_abs)} abs globals")
    draw_reads = set()
    for a in sorted(draw_abs):
        descs = draw_abs[a]
        if any(d.endswith('/r') for d in descs):
            draw_reads.add(a)
        print(f"    {a:#010x}  {', '.join(sorted(descs))}")
    # one level into its callees as well -- the hand-pointer positioning
    # may sit in a sub-draw function
    print("  -- draw callees --")
    for c in sorted(set(draw_calls)):
        insns = disasm_function(data, c)
        abs_g, _, _ = analyze(insns)
        reads = {a for a, d in abs_g.items() if any(x.endswith('/r') for x in d)}
        draw_reads |= reads
        if abs_g:
            print(f"  draw-callee {c:#010x}: " +
                  ", ".join(f"{a:#x}({'/'.join(sorted(abs_g[a]))})"
                            for a in sorted(abs_g)))

    # ---------- Intersection: handler-side writes vs draw-side reads ----
    print()
    print("--- Intersection: written by menu logic AND read by draw code -----")
    handler_writes = defaultdict(set)
    for h, insns in handler_insns.items():
        abs_g, _, _ = analyze(insns)
        for a, descs in abs_g.items():
            if any(d.endswith('/w') for d in descs):
                handler_writes[a].add(h)
    for a, fns in shared_write_globals.items():
        handler_writes[a].update(fns)
    hits = sorted(set(handler_writes) & draw_reads)
    for a in hits:
        print(f"  {a:#010x}  writers={[hex(w) for w in sorted(handler_writes[a])][:6]}")
    if not hits:
        print("  (none -- cursor must live in a heap/struct field, "
              "trace the widget pointer instead)")

    # ---------- Full listings -------------------------------------------
    print()
    print("--- Full listings ---------------------------------------------------")
    for f in FULL_LISTING:
        insns = handler_insns.get(f) or disasm_function(data, f)
        print()
        print(f"===== {f:#010x} =====")
        for insn in insns:
            print(f"  {insn.address:#010x}  {insn.mnemonic:<8s} {insn.op_str}")

    print()
    print(f"Log saved to: {_log_path}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
