#!/usr/bin/env python3
"""
ff7_defend_toggle_static.py -- where do the Defend/Change pseudo-commands
live? (2026-08-01, user report: Defend is inaudible.)

KNOWN (v2.9 research): the battle COMMAND widget's Left/Right-at-edge
paths generate pseudo-commands 0x12 (Change) / 0x13 (Defend) that are
NEVER stored in the per-slot command table the mod speaks from -- so the
on-screen "Attack" cell flips to "Defend" silently for our users.

THIS SCRIPT: disassemble the command-state handler
(BATTLE_MENU_FN_TABLE[1] @ 0x91E6B8, the state the mod calls
BMENU_STATE_COMMAND) plus one call level, and report every instruction
that stores an 0x12 or 0x13 immediate (or moves one into a register
that is then stored). The write target is the variable the renderer
draws the swapped label from -- the byte the mod needs to poll.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"defend_toggle_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

import capstone

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
]
exe_path = next((c for c in EXE_CANDIDATES if os.path.isfile(c)), None)
data = open(exe_path, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((va, vs, ro))

def v2o(va):
    r = va - image_base
    for sva, svs, sro in secs:
        if sva <= r < sva + svs:
            return sro + (r - sva)
    return None

FN_TABLE = 0x91E6B8
handlers = [struct.unpack_from('<I', data, v2o(FN_TABLE) + i * 4)[0]
            for i in range(32)]
print("fn table head:", ", ".join(f"[{i}]=0x{h:X}" for i, h in enumerate(handlers[:10])))
H_CMD = handlers[1]
print(f"\ncommand-state handler = fn[1] = 0x{H_CMD:X}\n")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def scan_func(fva, window=0x1400, label=""):
    """Print instructions involving 0x12/0x13 immediates + collect calls."""
    calls, hits = [], []
    off = v2o(fva)
    code = data[off:off + window]
    prev = None
    for insn in md.disasm(code, fva):
        if insn.id == 0:
            continue
        txt = f"{insn.mnemonic} {insn.op_str}"
        if insn.mnemonic == 'call':
            try:
                t = int(insn.op_str, 16)
                if 0x400000 <= t < 0x800000:
                    calls.append(t)
            except ValueError:
                pass
        interesting = False
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM and \
               (op.imm & 0xFFFFFFFF) in (0x12, 0x13):
                interesting = True
        if interesting:
            hits.append((insn.address, txt, prev))
        prev = (insn.address, txt)
        if txt.startswith('ret'):
            break
    if hits:
        print(f"--- {label} 0x{fva:X}: {len(hits)} hit(s) ---")
        for a, t, p in hits:
            if p:
                print(f"    (prev 0x{p[0]:X}: {p[1]})")
            print(f"  0x{a:X}: {t}")
    return calls

calls = scan_func(H_CMD, label="fn[1]")
seen = {H_CMD}
frontier = list(dict.fromkeys(calls))
depth = 0
while frontier and depth < 2:
    nxt = []
    for c in frontier:
        if c in seen:
            continue
        seen.add(c)
        nxt.extend(scan_func(c, label=f"callee d{depth+1}"))
    frontier = list(dict.fromkeys(nxt))
    depth += 1

# Also: full disasm of fn[1] to a section of the log for hand reading —
# the pseudo-command may be composed (mov reg,0x13 / store reg) across
# instructions the immediate filter shows without context.
print("\n===== fn[1] full disasm (hand-reading context) =====")
off = v2o(H_CMD)
for insn in md.disasm(data[off:off + 0x1400], H_CMD):
    if insn.id == 0:
        print(f"  0x{insn.address:X}: .byte {insn.bytes.hex()}")
        continue
    print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic.startswith('ret'):
        break
print("\nDone.")
