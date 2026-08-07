#!/usr/bin/env python3
"""
ff7_msgnum_static2.py -- FE DE number mechanism, part 2 (2026-08-07;
PARKED [DIALOGNUM] + [INNGIL]; companion to ff7_msgnum_static.py).

Part 1 proved MPARA/MPRA2 write per-window numeric params to
  word [0xCC08A0 + win*16 + slot*2]   (values)
  byte [0xCBFBE0 + win*8  + slot]     (bank nibbles)
and that NO other .text code references either base as an imm32 -- the
render side must reach the data through a derived pointer, a copy, or a
base constant just OUTSIDE the swept window.

THIS SCRIPT anchors on what the renderer must touch instead: the
per-window typewriter pointer array DIALOG_TEXT_PTRS 0xCBF578 (the
mod's oldest live-proven dialog global -- the byte-fetch loop that hits
0xFE lives wherever these pointers are read/advanced).

Steps:
  1. imm32 sweep for [0xCBF578, 0xCBF588) -- every reader/advancer of
     the typewriter pointers.
  2. imm32 sweep for near-miss bases below the part-1 windows:
     [0xCC0880, 0xCC08A0) and [0xCBFBC0, 0xCBFBE0) (a containing struct
     would put its base slightly below the arrays).
  3. Disassemble a wide window around every typewriter-ref site; flag
     function-code constants (0xFE, 0xDD, 0xDE, 0xE8...), any disp into
     the param/bank neighborhoods, and any indirect jmp through a jump
     table (the classic sub-code dispatch shape).
  4. Dump every discovered jump table's entries and briefly disassemble
     each target, looking for the one that renders a NUMBER (expect a
     divide-by-10 / 0x66666667 magic-constant loop or itoa-style calls,
     plus reads of the param/bank data).
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
    f"msgnum_static2_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
print(f"  {len(data):,} bytes\n")

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
    name = data[off:off+8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    sections.append((name, va, vs, rs, rp))

def va_to_off(va):
    rva = va - image_base
    for _, sva, svs, _, srp in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

TXTPTR_LO, TXTPTR_HI = 0xCBF578, 0xCBF588
PARAM_LO,  PARAM_HI  = 0xCC0880, 0xCC08E0   # arrays + a small halo
BANK_LO,   BANK_HI   = 0xCBFBC0, 0xCBFC20
FUNC_CONSTS = (0xFE, 0xDD, 0xDE, 0xDF, 0xE8, 0xE9)

text = next(s for s in sections if s[0] == '.text')
_, t_va, t_vs, t_rs, t_rp = text
t_size = min(t_vs, t_rs)
raw = data[t_rp:t_rp + t_size]

def sweep(lo, hi):
    out = []
    for i in range(t_size - 3):
        v = int.from_bytes(raw[i:i+4], 'little')
        if lo <= v < hi:
            out.append((image_base + t_va + i, v))
    return out

print("Step 1: typewriter-pointer references (0xCBF578..0xCBF587)")
tp_hits = sweep(TXTPTR_LO, TXTPTR_HI)
for s, v in tp_hits:
    print(f"  0x{s:08X} -> 0x{v:08X}")
print(f"  {len(tp_hits)} hits\n")

print("Step 2: near-miss bases below the arrays")
for lo, hi, tag in ((0xCC0880, 0xCC08A0, "param-halo"), (0xCBFBC0, 0xCBFBE0, "bank-halo")):
    for s, v in sweep(lo, hi):
        print(f"  [{tag}] 0x{s:08X} -> 0x{v:08X}")
print()

# Cluster typewriter refs into candidate functions.
clusters = []
for s, v in tp_hits:
    if clusters and s - clusters[-1][-1][0] <= 0x400:
        clusters[-1].append((s, v))
    else:
        clusters.append([(s, v)])
print(f"Step 3: {len(clusters)} typewriter-ref cluster(s)\n")

jump_tables = []   # (jmp_site, table_va, index_hint)

def dump_window(lo, hi, label):
    off = va_to_off(lo)
    print("=" * 74)
    print(label)
    print("=" * 74)
    flagged = 0
    for insn in md.disasm(bytes(data[off:off + (hi - lo)]), lo):
        note = ""
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                iv = op.imm & 0xFFFFFFFF
                if iv in FUNC_CONSTS and insn.mnemonic in ("cmp", "sub", "mov", "test", "and"):
                    note += f"   ; <<< func-const 0x{iv:02X}"
                    flagged += 1
            if op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
                dv = op.mem.disp & 0xFFFFFFFF
                if TXTPTR_LO <= dv < TXTPTR_HI:
                    note += "   ; <<< TXTPTR"
                elif PARAM_LO <= dv < PARAM_HI:
                    note += f"   ; <<< PARAM-area 0x{dv:08X}"
                elif BANK_LO <= dv < BANK_HI:
                    note += f"   ; <<< BANK-area 0x{dv:08X}"
        if insn.mnemonic == "jmp" and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_MEM and \
           insn.operands[0].mem.base == 0 and insn.operands[0].mem.scale == 4:
            tbl = insn.operands[0].mem.disp & 0xFFFFFFFF
            note += f"   ; <<< JUMP TABLE @0x{tbl:08X}"
            jump_tables.append((insn.address, tbl))
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{note}")
    print(f"  [{flagged} func-const flags]\n")

for ci, cl in enumerate(clusters):
    lo = (cl[0][0] - 0x180) & ~0xF
    hi = cl[-1][0] + 0x200
    dump_window(lo, hi, f"cluster {ci}: {len(cl)} TXTPTR ref(s) at "
                        f"{['0x%08X' % s for s, _ in cl]}")

print(f"\nStep 4: {len(jump_tables)} jump table(s) discovered")
seen = set()
for site, tbl in jump_tables:
    if tbl in seen:
        continue
    seen.add(tbl)
    toff = va_to_off(tbl)
    if toff is None:
        print(f"  table @0x{tbl:08X}: outside sections?!")
        continue
    # Heuristic entry count: read until an entry leaves .text.
    entries = []
    for i in range(64):
        e = struct.unpack_from('<I', data, toff + i * 4)[0]
        if not (image_base + t_va <= e < image_base + t_va + t_size):
            break
        entries.append(e)
    print(f"\n  table @0x{tbl:08X} (from jmp at 0x{site:08X}): "
          f"{len(entries)} in-text entries")
    for i, e in enumerate(entries):
        print(f"    [{i:2}] 0x{e:08X}")
    # Brief disasm of each distinct target.
    for e in sorted(set(entries)):
        dump_window(e, e + 0xA0, f"  jump-table target 0x{e:08X}")

print("Done.")
