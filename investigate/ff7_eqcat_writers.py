#!/usr/bin/env python3
"""
ff7_eqcat_writers.py -- every code site touching the equip category
cursor 0xDCA4A4 (2026-08-01).

Play report: Barret's equip screen entered with our cat byte = 1
("Armor: Bronze Bangle" spoken), then EVERY cursor move was silent and
the byte never changed while the pane flag DID move. Either the game's
row cursor truly froze (implausible -- sighted play works) or 0xDCA4A4
is not the LIVE cursor on this path (the v2.30.12 "a correlated cell,
not THE source" class, static edition).

Enumerate ALL instruction sites referencing 0xDCA4A4 game-wide, classify
read vs write, and print context for each WRITE -- if the only writers
are the 0x707079/0x7070C0 wrap sites plus an init, we look for what the
ROW RENDERER actually reads instead (imul row-height near a different
variable in the same draw path).
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"eqcat_writers_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

exe_path = next(c for c in (
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
) if os.path.isfile(c))
data = open(exe_path, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((va, vs, ro, rs))

# .text bounds (first section)
text_va, text_vs, text_ro, text_rs = secs[0]

def off_to_va(off):
    return image_base + text_va + (off - text_ro)

TARGET = 0xDCA4A4
needle = struct.pack('<I', TARGET)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

hits = []
pos = text_ro - 1
end = text_ro + text_rs
while True:
    pos = data.find(needle, pos + 1, end)
    if pos < 0:
        break
    # disasm a window straddling the hit so the instruction decodes whole
    for back in range(1, 12):
        start = pos - back
        insns = list(md.disasm(data[start:start + 16], off_to_va(start)))
        if not insns:
            continue
        ins = insns[0]
        if start + ins.size >= pos + 4 and TARGET in (
                (op.mem.disp & 0xFFFFFFFF) if op.type == capstone.x86.X86_OP_MEM
                else (op.imm & 0xFFFFFFFF) if op.type == capstone.x86.X86_OP_IMM
                else -1
                for op in ins.operands):
            access = []
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and \
                   (op.mem.disp & 0xFFFFFFFF) == TARGET:
                    if op.access & capstone.CS_AC_WRITE:
                        access.append('WRITE')
                    if op.access & capstone.CS_AC_READ:
                        access.append('read')
            hits.append((ins.address, f"{ins.mnemonic} {ins.op_str}",
                         '+'.join(access) or 'imm'))
            break

print(f"{len(hits)} instruction sites referencing 0x{TARGET:X}:\n")
for va, txt, acc in sorted(set(hits)):
    print(f"  0x{va:X}: [{acc:10s}] {txt}")

print("\nWRITE-site context (16 instructions before each):")
for va, txt, acc in sorted(set(hits)):
    if 'WRITE' not in acc:
        continue
    print(f"\n--- write @ 0x{va:X} ---")
    # rewind ~60 bytes and disasm forward to the write
    start_off = text_ro + (va - image_base - text_va) - 0x40
    for ins in md.disasm(data[start_off:start_off + 0x60],
                         off_to_va(start_off)):
        mark = "  <<<" if ins.address == va else ""
        print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{mark}")
        if ins.address > va:
            break
