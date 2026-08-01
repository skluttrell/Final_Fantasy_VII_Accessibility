#!/usr/bin/env python3
"""
ff7_magic_menu_static.py -- Statically map the MAGIC menu sub-screen
(2026-08-01; user report: the out-of-battle spell list is the one
main-menu screen the mod has never narrated -- Magic + PHS were the
two remaining gaps since v2.30.35).

WHY TABLE[2]: the dispatcher row->index pattern, three fixed points:
Item row 0 = index 1 (live-proven v2.31), Materia row 2 = index 3
(v2.30.33), Status row 4 = index 5 (FFNx name) => Magic row 1 = 2.
Cross-checked below against table[10] = 0x6FEDB0 (save menu, FFNx).

WHAT THE MAGIC MENU NEEDS SPOKEN (screen layout):
  - entry: "Magic. <character>" (CHARSEL_CHOSEN, the v2.32 pane)
  - top bar: Magic / Summon / Enemy Skill tab cursor
  - spell list: cursor+scroll -> magic index -> kernel2 magic name
    (ValidatedSection g_k2_magic_sig -- retranslation-safe since
    v2.30.47); learned set = a menu-built availability array (find it)
  - usable-outside-battle state (grayed rows): find what the renderer
    tests per row -- kernel magic-data restriction bit or a menu array
  - MP cost + current MP (savemap char record +0x30) for the
    "can't afford" state
  - I key: magic description (kernel2 section 11 -- head signature to
    be derived from kernel2.bin AFTER this dump names the reader)

METHOD: identical to the limit/materia/equip sessions -- full annotated
disasm of the sub + depth-2 mining of written BSS addresses, hand-read
the cursor semantics off the dump.
"""
import sys, os, struct, datetime, subprocess
from collections import defaultdict

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed.")
    sys.exit(1)

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"magic_menu_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def off_to_va(off):
    for sva, svs, srp in sections:
        if srp <= off < srp + svs:
            return image_base + sva + (off - srp)
    return None

def gav(addr, offset):
    off = va_to_off(addr + offset)
    return struct.unpack_from('<I', data, off)[0] if off is not None else None

CODE_LO, CODE_HI = 0x401000, 0x800000
MENU_MOD_LO, MENU_MOD_HI = 0x6C0000, 0x780000

# Dispatcher table from disk via the FFNx operand chain (never trust a
# cached constant): menu_sub_6CB56A + 0x2EC.
table_va = gav(0x6CB56A, 0x2EC)
toff = va_to_off(table_va)
tab = [struct.unpack_from('<I', data, toff + i*4)[0] for i in range(16)]
assert tab[10] == 0x6FEDB0, "table[10] save-menu cross-check FAILED -- stop"
MAGIC_SUB = tab[2]
print(f"menu_subs_call_table @ 0x{table_va:X}")
for i, v in enumerate(tab):
    known = {0: "main/timer", 1: "ITEM (live v2.31)", 2: "<= MAGIC (this hunt)",
             3: "materia v2.30.33", 4: "equip v2.30.34", 5: "status (FFNx)",
             7: "limit v2.30.35", 8: "config (FFNx)", 10: "save (FFNx)"}.get(i, "")
    print(f"  [{i:2d}] 0x{v:08X}  {known}")
print()

KNOWN = {
    0xDC04B4: "SAVEMAP_MATERIA[0]", 0xDC08B4: "SAVEMAP_GIL",
    0xDC1154: "MENU_CURSOR", 0xDC12DC: "MENU_OPEN",
    0xDC12EC: "MENU_DISPATCH_INDEX", 0xDC1288: "CHARSEL_CHOSEN",
    0xDC12E8: "MENU_DISPATCH_FADE", 0xDC0DDE: "char-avail mask",
    0xDC1130: "main-menu disabled-row bits", 0xDC1210: "dispatcher parity toggle",
}
def annot(addr):
    if addr in KNOWN:
        return KNOWN[addr]
    if 0xDC04B4 <= addr < 0xDC04B4 + 800:
        return f"SAVEMAP_MATERIA[{(addr-0xDC04B4)//4}]"
    if 0xDBFD8C <= addr < 0xDC0230:
        rec = (addr - 0xDBFD8C) // 0x84
        off = (addr - 0xDBFD8C) % 0x84
        tag = ""
        if off == 0x30: tag = " (cur MP)"
        elif off == 0x3A: tag = " (max MP)"
        elif 0x40 <= off < 0x60: tag = f" (weapon materia[{(off-0x40)//4}])"
        elif 0x60 <= off < 0x80: tag = f" (armor materia[{(off-0x60)//4}])"
        return f"charrec{rec}+0x{off:X}{tag}"
    if 0xDBFD38 <= addr < 0xDC0E38:
        return f"savemap+0x{addr-0xDBFD38:X}"
    return None

def ff7_encode(s):
    return bytes((ord(c) - 0x20) & 0xFF for c in s)

STR_VAS = {}
for label in ("Summon", "Enemy Skill", "MP", "Magic"):
    pat = ff7_encode(label)
    start, hits = 0, []
    while True:
        idx = data.find(pat, start)
        if idx < 0:
            break
        va = off_to_va(idx)
        if va is not None and 0x900000 <= va < 0x9F0000:
            hits.append(va)
            STR_VAS[va] = label
        start = idx + 1
    print(f'"{label}": ' + (", ".join(f"0x{v:X}" for v in hits[:6]) if hits else "none"))
print()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

SUB_LEN = 0x3000

def dump_disasm(fva, length, title):
    print(f"===== {title} @ 0x{fva:X} (len 0x{length:X}) =====")
    foff = va_to_off(fva)
    code = data[foff:foff + length]
    for insn in md.disasm(code, fva):
        if insn.id == 0:
            print(f"  0x{insn.address:X}: .byte {insn.bytes.hex()}")
            continue
        notes = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM:
                imm = op.imm & 0xFFFFFFFF
                if imm in STR_VAS:
                    notes.append(f'-> "{STR_VAS[imm]}"')
                elif annot(imm):
                    notes.append(f"imm={annot(imm)}")
            if op.type == capstone.x86.X86_OP_MEM:
                d = op.mem.disp & 0xFFFFFFFF
                an = annot(d)
                if an:
                    notes.append(an)
                elif d in STR_VAS:
                    notes.append(f'"{STR_VAS[d]}"')
        line = f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}"
        if notes:
            line += "   ; " + " ".join(notes)
        print(line)
    print()

dump_disasm(MAGIC_SUB, SUB_LEN, "magic_menu_sub (table[2])")

FUNC_WINDOW = 0x1800
MAX_DEPTH = 2
_func_cache = {}

def sweep_func(fva, window=FUNC_WINDOW):
    if fva in _func_cache:
        return _func_cache[fva]
    reads, writes, callees = defaultdict(list), defaultdict(list), []
    foff = va_to_off(fva)
    if foff is not None:
        code = data[foff:foff + window]
        for insn in md.disasm(code, fva):
            if insn.id == 0:
                continue
            if insn.mnemonic == 'call':
                try:
                    tgt = int(insn.op_str, 16)
                    if MENU_MOD_LO <= tgt < MENU_MOD_HI:
                        callees.append(tgt)
                except ValueError:
                    pass
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    tgt = op.mem.disp & 0xFFFFFFFF
                    if not (0x900000 <= tgt < 0xDE0000):
                        continue
                    plain = (op.mem.base == 0 and op.mem.index == 0)
                    rec = (insn.address,
                           f"{insn.mnemonic} {insn.op_str}" +
                           ("" if plain else "  [indexed]"))
                    if op.access & capstone.CS_AC_WRITE:
                        writes[tgt].append(rec)
                    if op.access & capstone.CS_AC_READ:
                        reads[tgt].append(rec)
    result = (reads, writes, callees)
    _func_cache[fva] = result
    return result

print("===== mining: magic sub + callees depth 2 =====")
all_reads, all_writes = defaultdict(list), defaultdict(list)
seen, frontier = set(), [(MAGIC_SUB, 0)]
sweep_func(MAGIC_SUB, SUB_LEN)
while frontier:
    fva, depth = frontier.pop()
    if fva in seen:
        continue
    seen.add(fva)
    reads, writes, callees = sweep_func(fva)
    for k, v in reads.items():
        all_reads[k].extend((fva, *r) for r in v)
    for k, v in writes.items():
        all_writes[k].extend((fva, *r) for r in v)
    if depth < MAX_DEPTH:
        frontier.extend((c, depth + 1) for c in set(callees))
print(f"functions swept: {len(seen)}")

addrs = sorted(all_writes.keys())
clusters, cur = [], []
for a in addrs:
    if cur and a - cur[-1] > 0x40:
        clusters.append(cur)
        cur = []
    cur.append(a)
if cur:
    clusters.append(cur)

print(f"\nWRITTEN clusters ({len(clusters)}):")
for cl in clusters:
    print(f"\n  cluster 0x{cl[0]:X} .. 0x{cl[-1]:X} ({len(cl)} addrs)")
    for a in cl:
        wrec = all_writes[a]
        rrec = all_reads.get(a, [])
        an = annot(a) or ""
        print(f"    0x{a:X}  W={len(wrec)} R={len(rrec)}  {an}")
        for fva, iva, txt in wrec[:4]:
            tag = ("sub+0x%X" % (iva - MAGIC_SUB)) if 0 <= iva - MAGIC_SUB < SUB_LEN else ("fn 0x%X" % fva)
            print(f"        w @0x{iva:X} ({tag}): {txt}")
        for fva, iva, txt in rrec[:2]:
            print(f"        r @0x{iva:X}: {txt}")
print("\nDone.")
