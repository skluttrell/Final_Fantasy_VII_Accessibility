#!/usr/bin/env python3
"""
ff7_idlck_static.py -- Statically locate FF7's walkmesh triangle-LOCK state
(the IDLCK opcode's runtime storage) in ff7_en.exe on disk (2026-07-23).

WHY:
  Player report (7th Heaven bar, log 17:53): the pathfinder routed the player
  INTO the area behind Tifa's bar counter -- A* legitimately found a path
  because the walkmesh ACCESS pool connects those triangles (the game-wide
  offline dry run proved the pool 100% reciprocal), yet the game blocks the
  player from walking there. The game's mechanism for counters/doorways is
  the IDLCK field opcode ("triangle lock"): scripts mark specific walkmesh
  triangles impassable at runtime, overlaying the static access pool.

  The mod's A* (v2.22 turn-by-turn) reads only the static pool, so routes
  cross locked triangles and the player walks into an invisible wall. To fix
  it, A* must treat locked triangles as walls -- which requires finding WHERE
  the lock state lives at runtime.

  IDLCK = opcode 0x6D (FFNx FieldOpcode enum, counted with anchors that all
  match already-hooked table entries: STTIM=0x38, MESSAGE=0x40, MPNAM=0x43,
  ASK=0x48, TLKON=0x7E).

HOW (all from the exe on disk -- zero live process interaction):
  1. execute_opcode_table via the mod's own Resolve() chain (validated with
     the same MESSAGE/ASK cross-checks every prior table script used).
  2. Disassemble table[0x6D] (IDLCK) -- its script-arg reads and memory
     writes reveal the lock table (base + stride/format). Neighbors 0x6C
     (FADEW) and 0x6E (LSTMP) are disassembled as identity checks: if 0x6D's
     handler doesn't look like "read u16 triangle id + u8 flag, write state",
     the enum count was wrong and the neighbors tell us which way to shift.
  3. XREF SCAN: search all code for other instructions referencing the
     discovered base address(es) -- the READ side (the game's own movement/
     collision code consulting the lock) proves the semantics: what value
     means locked, and whether movement checks it per-triangle or per-edge.

Output: annotated listings + write/read summaries + xref list. Feeds the A*
edge-filter change in proxy.cpp (and, per the memory-map rule, new §4/§14
rows once confirmed).

Requires capstone (already in investigate/venv).
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
    f"idlck_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- locate the exe on disk ------------------------------------------------------
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

# -- minimal PE parse ------------------------------------------------------------
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
    flags = struct.unpack_from('<I', data, off + 36)[0]
    sections.append((va, vs, rp, rs, name, flags))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp, srs, _, _ in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

def grc(addr, offset):
    off = va_to_off(addr + offset)
    if off is None or data[off] != 0xE8:
        return None
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return addr + offset + 5 + rel

def gav(addr, offset):
    off = va_to_off(addr + offset)
    return struct.unpack_from('<I', data, off)[0] if off is not None else None

CODE_LO, CODE_HI = 0x401000, 0x9FFFFF

# -- Step 1: resolve the opcode table --------------------------------------------
FIELD_INIT_EVENT = 0x60BACF
execute_opcode = grc(FIELD_INIT_EVENT, 0x80)
print(f"execute_opcode       = grc(0x{FIELD_INIT_EVENT:X}, 0x80)  = "
      f"{'0x%08X' % execute_opcode if execute_opcode else 'FAIL'}")
if not execute_opcode or not (CODE_LO <= execute_opcode <= CODE_HI):
    print("CHAIN INVALID -- execute_opcode out of range, aborting.")
    sys.exit(1)

table_va = gav(execute_opcode, 0x10D)
print(f"execute_opcode_table = gav(^, 0x10D)            = 0x{table_va:08X}")
table_off = va_to_off(table_va)
if table_off is None:
    print("CHAIN INVALID -- table VA not in any section, aborting.")
    sys.exit(1)

entries = struct.unpack_from('<256I', data, table_off)

# -- Step 2: cross-checks ---------------------------------------------------------
msg = entries[0x40]
ask = entries[0x48]
msg_ok = CODE_LO <= msg <= CODE_HI
call_ok = msg_ok and data[va_to_off(msg + 0x3B)] == 0xE8
ask_ok = CODE_LO <= ask <= CODE_HI
print(f"\nCross-checks:")
print(f"  table[0x40] MESSAGE = 0x{msg:08X}  in exe code range          {'OK' if msg_ok else '** FAIL **'}")
print(f"  byte at MESSAGE+0x3B = 0x{data[va_to_off(msg + 0x3B)]:02X}  expect E8 (FFNx walk)      {'OK' if call_ok else '** FAIL **'}")
print(f"  table[0x48] ASK     = 0x{ask:08X}  in exe code range          {'OK' if ask_ok else '** FAIL **'}")
if not (msg_ok and call_ok and ask_ok):
    print("CROSS-CHECKS FAILED -- do not trust the table, aborting.")
    sys.exit(1)
print("ALL CROSS-CHECKS PASSED.\n")

# -- Step 3: disassemble IDLCK + identity-check neighbors -------------------------
TARGETS = [
    (0x6C, "FADEW", "fade-wait (identity check: should poll a fade flag, no array writes)"),
    (0x6D, "IDLCK", "TRIANGLE LOCK -- the target: expect u16 triangle id + u8 flag args"),
    (0x6E, "LSTMP", "load stamp? (identity check)"),
]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_handler(va, max_bytes=0x600):
    off = va_to_off(va)
    code = data[off:off + max_bytes]
    lines, writes, reads, indexed = [], {}, {}, []
    max_fwd = va
    end_va = va + max_bytes
    for insn in md.disasm(code, va):
        markers = []
        if insn.group(capstone.CS_GRP_JUMP) and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            tgt = insn.operands[0].imm
            if va < tgt < end_va:
                max_fwd = max(max_fwd, tgt)
        for i, op in enumerate(insn.operands):
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            m = op.mem
            if m.base == 0 and m.index == 0 and m.disp > 0x400000:
                is_write = (i == 0 and insn.mnemonic.startswith(
                    ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                d = writes if is_write else reads
                d.setdefault(m.disp, []).append(insn.address)
                markers.append(f"{'W' if is_write else 'R'} GLOBAL[0x{m.disp:08X}]")
            elif m.index != 0 and m.disp > 0x400000:
                # disp + (optional base) + reg*scale = static array access.
                is_write = (i == 0 and insn.mnemonic.startswith(
                    ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                indexed.append((m.disp, m.scale, insn.address, is_write))
                markers.append(f"ARRAY[0x{m.disp:08X} + reg*{m.scale}]{' W' if is_write else ' R'}")
        # get_field_parameter pattern: script[pos + 1 + N] -- mark the calls
        if insn.mnemonic == 'call' and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            markers.append(f"CALL 0x{insn.operands[0].imm:08X}")
        lines.append(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}"
                     + (f"   ; {' | '.join(markers)}" if markers else ""))
        if insn.mnemonic.startswith('ret') and insn.address >= max_fwd:
            break
    return lines, writes, reads, indexed

all_candidates = set()
for opnum, name, why in TARGETS:
    va = entries[opnum]
    print("=" * 70)
    print(f"opcode[0x{opnum:02X}] {name} handler = 0x{va:08X}")
    print(f"  ({why})")
    print("=" * 70)
    if not (CODE_LO <= va <= CODE_HI):
        print("  NOT an exe code address -- enum count wrong for this slot?\n")
        continue
    lines, writes, reads, indexed = disasm_handler(va)
    for l in lines:
        print(l)
    print(f"\n  -- {name} absolute-global WRITES:")
    for a, sites in sorted(writes.items()):
        print(f"     0x{a:08X}  at {', '.join('0x%X' % s for s in sites)}")
        if opnum == 0x6D:
            all_candidates.add(a)
    print(f"  -- {name} absolute-global READS:")
    for a, sites in sorted(reads.items()):
        print(f"     0x{a:08X}  at {', '.join('0x%X' % s for s in sites)}")
    print(f"  -- {name} indexed-array accesses (disp + reg*scale):")
    for disp, scale, site, is_w in indexed:
        print(f"     0x{disp:08X} + reg*{scale}  {'WRITE' if is_w else 'read '}  at 0x{site:X}")
        if opnum == 0x6D:
            all_candidates.add(disp)
    print()

# -- Step 4: xref scan for the candidate bases ------------------------------------
# The READ side (movement/collision consulting the lock) is the proof of
# semantics. Scan every executable section for the candidate addresses as
# little-endian imm32/disp32, then disassemble a few instructions around each
# hit for context.
print("=" * 70)
print("XREF SCAN for IDLCK write targets across all code sections")
print("=" * 70)
if not all_candidates:
    print("  (no candidates found in the IDLCK handler -- nothing to scan)")
for cand in sorted(all_candidates):
    needle = struct.pack('<I', cand)
    hits = []
    for sva, svs, srp, srs, name, flags in sections:
        if not (flags & 0x20000000):     # IMAGE_SCN_MEM_EXECUTE
            continue
        blob = data[srp:srp + min(svs, srs)]
        idx = blob.find(needle)
        while idx != -1:
            hits.append(image_base + sva + idx)
            idx = blob.find(needle, idx + 1)
    print(f"\n  candidate 0x{cand:08X}: {len(hits)} raw hit(s) in code sections")
    for h in hits[:40]:
        # Disassemble a window starting a bit before the hit so the
        # instruction containing the imm is shown in context.
        start = h - 8
        off = va_to_off(start)
        ctx = []
        if off is not None:
            for insn in md.disasm(data[off:off + 24], start):
                ctx.append(f"0x{insn.address:08X} {insn.mnemonic} {insn.op_str}")
                if len(ctx) >= 4:
                    break
        print(f"     imm at 0x{h:08X}:")
        for c in ctx:
            print(f"        {c}")

print("\nDone. Next: identify the lock table among the candidates (the one the")
print("xref scan shows MOVEMENT code reading), note stride/format, then wire it")
print("into proxy.cpp's A* edge filter + reachability announcement.")
