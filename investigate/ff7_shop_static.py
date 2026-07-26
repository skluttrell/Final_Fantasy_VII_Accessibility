#!/usr/bin/env python3
"""
ff7_shop_static.py -- Statically map the SHOP menu module (2026-07-26; user
request: connect the shop menus + gil key).

WHAT THE SHOP NEEDS SPOKEN (Screenshots/Menus/Shop/item_shop_1/2.jpg):
  - top bar cursor: Buy / Sell / Exit (+ the greeting line "Welcome!")
  - buy list: which row is highlighted -> item name + price + gil on hand
  - sell list: inventory/materia row -> name + sell price ("What would you
    like to sell?"; materia rows show Price through AP / Price for Master /
    Owned / Equipped and the equip-effect pane)
  - quantity selector: "how many" count while buying/selling
  - I key: description of the highlighted ware (kernel descriptions --
    already-shipped infra; no new addresses needed for the TEXT)

WHY THE SHOP IS NOT ANOTHER menu_subs_call_table SCREEN:
  FFNx ff7_data.h line 1442-1444 reaches the shop OUTSIDE that table:
      menu_sub_6CBD54   = get_relative_call(menu_sub_6CDA83, 0xC1)
      menu_sub_71FF95   = get_relative_call(menu_sub_6CBD54, 0x7)
      menu_shop_loop    = get_relative_call(menu_sub_71FF95, 0x84)
  menu_sub_6CDA83 is the MENU MODULE's per-menu-TYPE dispatcher (other
  branches: +0x20 battle-end screens, +0x9A name entry, +0xAF -> 6CBD43
  -> PHS, +0xDE -> 6CB56A = the main-menu dispatcher we already hook).
  So the shop has its own top-level branch, selected by some menu-type
  variable this script must FIND -- that variable is the mod's gate for
  "a shop is open", the shop's equivalent of MENU_DISPATCH_INDEX.

METHOD (exe on disk, zero live interaction -- the item/battle-menu recipe):
  1. Verify the chain by its two name-embedded anchors: the call operand at
     0x6CDA83+0xC1 MUST land on 0x6CBD54 and the one at 0x6CBD54+0x7 MUST
     land on 0x71FF95 (FFNx names embed US-1.02 VAs; no ASLR). Then the
     call at 0x71FF95+0x84 IS the shop loop -- no guessing.
  2. Dump the FULL disasm of 6CDA83's dispatch head (through all the FFNx
     branch offsets, ~0x140 bytes) so the menu-type variable and the shop's
     type value can be read straight off the cmp/switch code.
  3. Dump 71FF95 (the shop wrapper) and the WHOLE shop loop, annotated:
     known addresses (savemap gil 0xDC08B4, items array, MENU_OPEN...),
     FF7-encoded caption strings ("Buy"/"Sell"/"Exit"/"Welcome..."), and
     call targets. The sell-price call sites shop_loop+0x327B/+0x3373
     (FFNx replaces both with ff7_get_materia_gil) date-stamp the dump: if
     those offsets are NOT call instructions, the loop moved -- stop.
  4. Mine shop-loop code (entry + menu-module callees, depth 2) for plain
     [imm32] BSS accesses, clustered, with read/write splits -- the shop's
     state block (mode/cursors/scroll/quantity) must be in the WRITE set.
     Candidate semantics get hand-read from the annotated disasm; live
     confirmation rides the shipped build's debug logging (the FOCUS_MODE
     precedent), with a guided scan script as fallback.
"""
import sys, os, struct, datetime, subprocess
from collections import defaultdict

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed. Run: venv/Scripts/python.exe -m pip install capstone")
    sys.exit(1)

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"shop_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def get_relative_call(addr, offset):
    """FFNx get_relative_call: E8 rel32 at addr+offset -> absolute target."""
    off = va_to_off(addr + offset)
    assert off is not None, f"VA 0x{addr+offset:X} not mapped"
    opcode = data[off]
    assert opcode == 0xE8, (
        f"byte at 0x{addr+offset:X} is 0x{opcode:02X}, not E8 CALL -- "
        f"chain broke, DO NOT TRUST")
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return (addr + offset + 5 + rel) & 0xFFFFFFFF

# -- known landmarks -------------------------------------------------------------
MENU_TYPE_DISPATCH = 0x6CDA83   # FFNx menu_sub_6CDA83 (name-embedded VA)
SHOP_WRAP_A        = 0x6CBD54   # FFNx local menu_sub_6CBD54
SHOP_WRAP_B        = 0x71FF95   # FFNx menu_sub_71FF95
CODE_LO, CODE_HI   = 0x401000, 0x800000
MENU_MOD_LO, MENU_MOD_HI = 0x6C0000, 0x780000  # widened: shop code is 0x71-72xxxx

KNOWN = {
    0xDC08B4: "SAVEMAP_GIL(+0xB7C)", 0xDC1154: "MENU_CURSOR",
    0xDC12DC: "MENU_OPEN", 0xDC12EC: "MENU_DISPATCH_INDEX",
    0xDC12E8: "MENU_DISPATCH_TRANS", 0xDC0234: "SAVEMAP_ITEMS[0]",
    0xDC0BA4: "?GAME_MODE_REGION", 0xCC0D89: "GAME_MODE(0xCC0D89)",
    0xDC1130: "MENU_DISABLED_ROWS", 0xDC1324: "MENU_FOCUS_MODE",
}
# savemap materia array: FFNx savemap struct puts materia[200] u32 right
# after items[320] u16 -> 0xDC0234 + 640 = 0xDC04B4 (annotation only).
KNOWN[0xDC04B4] = "SAVEMAP_MATERIA[0]"
for a in range(0xDC0234, 0xDC0234 + 640, 2):
    pass  # (range annotated on the fly below, not per-address)

def annot(addr):
    if addr in KNOWN:
        return KNOWN[addr]
    if 0xDC0234 <= addr < 0xDC04B4:
        return f"SAVEMAP_ITEMS[{(addr-0xDC0234)//2}]"
    if 0xDC04B4 <= addr < 0xDC04B4 + 800:
        return f"SAVEMAP_MATERIA[{(addr-0xDC04B4)//4}]"
    if 0xDBFD38 <= addr < 0xDC0E38:
        return f"savemap+0x{addr-0xDBFD38:X}"
    return None

# -- FF7-encoded caption strings -------------------------------------------------
def ff7_encode(s):
    return bytes((ord(c) - 0x20) & 0xFF for c in s) + b'\xff'

STR_VAS = {}
for label in ("Buy", "Sell", "Exit", "Welcome", "How many", "Price through AP",
              "Price for Master", "Owned", "Equipped", "Gil remaining",
              "What would you"):
    pat = ff7_encode(label)[:-1]   # no terminator: greetings continue past it
    start, hits = 0, []
    while True:
        idx = data.find(pat, start)
        if idx < 0:
            break
        va = off_to_va(idx)
        if va is not None:
            hits.append(va)
            STR_VAS[va] = label
        start = idx + 1
    print(f'FF7-encoded "{label}": ' +
          (", ".join(f"0x{v:X}" for v in hits[:8]) +
           (f" (+{len(hits)-8} more)" if len(hits) > 8 else "")
           if hits else "NOT FOUND"))
print()

# -- resolve + verify the chain --------------------------------------------------
a = get_relative_call(MENU_TYPE_DISPATCH, 0xC1)
assert a == SHOP_WRAP_A, f"0x6CDA83+0xC1 -> 0x{a:X} != 0x6CBD54 -- STOP"
b = get_relative_call(SHOP_WRAP_A, 0x7)
assert b == SHOP_WRAP_B, f"0x6CBD54+0x7 -> 0x{b:X} != 0x71FF95 -- STOP"
shop_loop = get_relative_call(SHOP_WRAP_B, 0x84)
print(f"CHAIN VERIFIED: 6CDA83 --0xC1--> 6CBD54 --0x7--> 71FF95 --0x84--> "
      f"menu_shop_loop = 0x{shop_loop:X}")

# Date-stamp: FFNx replaces CALLs at shop_loop+0x327B and +0x3373 with its
# ff7_get_materia_gil. Both bytes must be E8 in the on-disk image.
for probe in (0x327B, 0x3373):
    poff = va_to_off(shop_loop + probe)
    byte = data[poff] if poff is not None else None
    tgt = get_relative_call(shop_loop, probe) if byte == 0xE8 else None
    print(f"  probe shop_loop+0x{probe:X}: byte=0x{byte:02X} "
          f"{'CALL -> 0x%X (get_materia_gil) OK' % tgt if byte == 0xE8 else 'NOT A CALL -- layout moved!'}")
print()

# -- full annotated disasm dumps -------------------------------------------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def dump_disasm(fva, length, title):
    """Full annotated linear disasm. RESTARTS past undecodable bytes
    (skipdata) -- the v2.30.26 capstone lesson: a stopped sweep silently
    truncates."""
    print(f"===== {title} @ 0x{fva:X} (len 0x{length:X}) =====")
    foff = va_to_off(fva)
    if foff is None:
        print("  NOT MAPPED")
        return
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
                disp = op.mem.disp & 0xFFFFFFFF
                an = annot(disp)
                if an:
                    notes.append(an)
                elif disp in STR_VAS:
                    notes.append(f'"{STR_VAS[disp]}"')
        if insn.mnemonic == 'call':
            try:
                tgt = int(insn.op_str, 16)
                notes.append(f"(+0x{insn.address - fva:X} from entry)")
            except ValueError:
                pass
        line = f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}"
        if notes:
            line += "   ; " + " ".join(notes)
        print(line)
    print()

# 1) the menu-TYPE dispatcher head: the cmp/switch on the menu-type global
#    (branch offsets from FFNx: 0x20, 0x9A, 0xAF, 0xC1, 0xDE all in range).
dump_disasm(MENU_TYPE_DISPATCH, 0x160, "menu_sub_6CDA83 MENU-TYPE DISPATCH")

# 2) the two wrappers (small).
dump_disasm(SHOP_WRAP_A, 0x40,  "menu_sub_6CBD54 (shop wrapper A)")
dump_disasm(SHOP_WRAP_B, 0x100, "menu_sub_71FF95 (shop wrapper B)")

# 3) THE SHOP LOOP -- full dump. Offsets reach past 0x3373; window 0x3800.
SHOP_LEN = 0x3800
dump_disasm(shop_loop, SHOP_LEN, "menu_shop_loop FULL")

# -- BSS mining across shop loop + callees ---------------------------------------
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

print("===== BSS/data mining: shop loop + menu-module callees (depth 2) =====")
all_reads, all_writes = defaultdict(list), defaultdict(list)
seen, frontier = set(), [(shop_loop, 0)]
# the shop loop itself is bigger than the standard window
_func_cache.clear()
sweep_func(shop_loop, SHOP_LEN)
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

# Cluster written addresses (gap > 0x40 starts a new cluster) -- the shop
# state block should stand out as a tight written cluster.
addrs = sorted(all_writes.keys())
clusters, cur = [], []
for aaddr in addrs:
    if cur and aaddr - cur[-1] > 0x40:
        clusters.append(cur)
        cur = []
    cur.append(aaddr)
if cur:
    clusters.append(cur)

print(f"\nWRITTEN address clusters ({len(clusters)}):")
for cl in clusters:
    print(f"\n  cluster 0x{cl[0]:X} .. 0x{cl[-1]:X} ({len(cl)} addrs)")
    for aaddr in cl:
        wrec = all_writes[aaddr]
        rrec = all_reads.get(aaddr, [])
        an = annot(aaddr) or ""
        print(f"    0x{aaddr:X}  W={len(wrec)} R={len(rrec)}  {an}")
        for fva, iva, txt in wrec[:4]:
            print(f"        w @0x{iva:X} ({'shop_loop+0x%X' % (iva - shop_loop) if 0 <= iva - shop_loop < SHOP_LEN else 'fn 0x%X' % fva}): {txt}")
        for fva, iva, txt in rrec[:2]:
            print(f"        r @0x{iva:X}: {txt}")

print("\nDone. Hand-read the annotated shop-loop dump for cursor/mode "
      "semantics; the written clusters above are the candidate state block.")
