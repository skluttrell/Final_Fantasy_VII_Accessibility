#!/usr/bin/env python3
"""
ff7_talk_range_static.py -- how does the game's OK-button talk check
actually measure distance? (2026-07-25 evening play report: no proximity
chirp near Barret outside 7th Heaven.)

THE CONTRADICTION THAT FORCES THIS: Barret's talk_radius is 70 but his
collision radius is 48 -- the player's center can never get closer than
80 (48+32) to his center, yet talking to him WORKS (this morning's log:
blocked at dist=81, then the talk ushered the player inside). So the
game's talk test cannot be center-distance <= talk_radius (the mod's
v2.27 proximity-chirp condition, which therefore NEVER fires for
large-bodied NPCs). The real test must incorporate the collision radii
somehow; this script finds the code and reads the formula.

METHOD (static, exe on disk = runtime image, no ASLR):
  talk_radius lives at field_event_data +0x74 (confirmed). The talk
  check must read it. Scan the field module's address range for
  word-size reads of [reg+0x74], then disassemble a window around each
  hit looking for the distance comparison -- specifically whether the
  code also reads +0x72 (collision radius) and adds it (the edge-based
  formula) before comparing.

KNOWN +0x74 READERS TO EXPECT (and rule out): the mod's own docs list
none in the engine yet -- talk_radius was confirmed via FFNx's struct
field order, not via a consumer disasm, so every hit here is new
information. The TLKON handler (0x618A80) writes +0x61 and may sit
nearby; MESSAGE/ASK handlers do not touch +0x74.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"talk_range_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

try:
    import capstone
except ImportError:
    print("ERROR: capstone not available -- run inside investigate/venv")
    sys.exit(1)

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
]
exe = next((c for c in EXE_CANDIDATES if os.path.isfile(c)), None)
if not exe:
    print("ERROR: ff7_en.exe not found")
    sys.exit(1)
print(f"Reading: {exe}")
data = open(exe, 'rb').read()

# PE parse: find .text section VA range + file offset mapping.
pe_off = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
image_base = struct.unpack_from('<I', data, pe_off + 24 + 28)[0]
sec_table = pe_off + 24 + opt_size
text_va = text_raw = text_size = None
for i in range(n_sec):
    off = sec_table + i * 40
    name = data[off:off + 8].rstrip(b'\0')
    if name == b'.text':
        text_size = struct.unpack_from('<I', data, off + 8)[0]
        text_va   = image_base + struct.unpack_from('<I', data, off + 12)[0]
        text_raw  = struct.unpack_from('<I', data, off + 20)[0]
        break
print(f".text: VA 0x{text_va:X} size 0x{text_size:X} raw 0x{text_raw:X}")

# Field module range (research doc: field opcode handlers 0x60xxxx-0x63xxxx,
# movement code 0x636xxx). First pass over 0x600000-0x660000 found ONLY
# the model-init writer (0x60C3xx: +0x72 default = scale*0x1E>>9, +0x74
# default = scale*0x50>>9) -- the CHECK reads through some other pattern
# or address. Widened to the whole .text; EBP-based accesses are kept
# when an INDEX register is present (optimized struct walks), dropped
# otherwise (stack-frame noise).
LO, HI = 0x401000, 0x7B0000

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def va_to_raw(va):
    return text_raw + (va - text_va)

code = data[va_to_raw(LO):va_to_raw(HI)]

# Pass 1: linear sweep; collect instructions whose memory operand has
# disp 0x74 (and separately 0x72) with a base register (not ESP/EBP
# stack frames -- struct access uses general regs).
hits74 = []
# capstone's disasm STOPS at the first undecodable byte; iterate with a
# manual restart (+1) so embedded data can't truncate the sweep.
def sweep(code_bytes, base_va):
    off = 0
    n = len(code_bytes)
    while off < n:
        got = False
        for ins in md.disasm(code_bytes[off:off + 0x4000], base_va + off):
            got = True
            yield ins
            off += ins.size
        if not got:
            off += 1     # undecodable byte: skip it and resume
for ins in sweep(code, LO):
    for op in ins.operands:
        if op.type != capstone.x86.X86_OP_MEM or op.mem.disp != 0x74:
            continue
        if op.mem.base in (capstone.x86.X86_REG_ESP, 0):
            continue
        if op.mem.base == capstone.x86.X86_REG_EBP and op.mem.index == 0:
            continue          # plain stack local
        # word-size loads only (talk_radius is s16): movsx/movzx/mov ax
        if ins.mnemonic not in ('movsx', 'movzx') and \
           not (ins.mnemonic == 'mov' and 'word ptr' in ins.op_str):
            continue
        hits74.append(ins.address)
print(f"\n[*+0x74] word accesses across .text: {len(hits74)}")

# Pass 2: for each hit, disassemble a +-0x60 byte window and print, and
# grep the window for +0x72 / +0x0C (model_pos) accesses -- the talk
# check must combine position distance with the radii.
for va in hits74:
    lo = max(LO, va - 0x60)
    window = data[va_to_raw(lo):va_to_raw(va + 0x80)]
    lines = []
    has72 = has0c = False
    for ins in md.disasm(window, lo):
        mark = "  <== +0x74" if ins.address == va else ""
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and \
               op.mem.base not in (capstone.x86.X86_REG_ESP,
                                   capstone.x86.X86_REG_EBP, 0):
                if op.mem.disp == 0x72:
                    has72 = True
                    mark += "  <== +0x72 (collision radius!)"
                elif op.mem.disp == 0x0C:
                    has0c = True
        lines.append(f"    0x{ins.address:06X}  {ins.mnemonic:8s} {ins.op_str}{mark}")
    print(f"\n--- hit at 0x{va:06X}  (window reads +0x72: {has72}, "
          f"+0x0C pos: {has0c}) ---")
    for l in lines:
        print(l)

# -- pass 3: the talk-disabled byte (+0x61) READERS ------------------------------
# TLKON's WRITER is known (0x618A80). The OK-press talk dispatch must
# READ +0x61 (skip disabled entities) right next to its range check --
# a byte access at an odd offset is a much rarer pattern than +0x74.
print("\n\n=== [*+0x61] byte reads (talk-disabled consumers) ===")
hits61 = []
for ins in sweep(code, LO):
    for op in ins.operands:
        if op.type != capstone.x86.X86_OP_MEM or op.mem.disp != 0x61:
            continue
        if op.mem.base in (capstone.x86.X86_REG_ESP, 0):
            continue
        if op.mem.base == capstone.x86.X86_REG_EBP and op.mem.index == 0:
            continue
        if ins.mnemonic not in ('movsx', 'movzx', 'cmp', 'test') and \
           not (ins.mnemonic == 'mov' and 'byte ptr' in ins.op_str):
            continue
        hits61.append(ins.address)
print(f"candidates: {len(hits61)}")
for va in hits61:
    lo = max(LO, va - 0xA0)
    window = data[va_to_raw(lo):va_to_raw(va + 0xC0)]
    lines = []
    tags = set()
    for ins in md.disasm(window, lo):
        mark = "  <== +0x61" if ins.address == va else ""
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and \
               op.mem.base not in (capstone.x86.X86_REG_ESP, 0):
                if op.mem.disp == 0x74:
                    tags.add('talk74')
                    mark += "  <== +0x74 talk_radius"
                elif op.mem.disp == 0x72:
                    tags.add('col72')
                    mark += "  <== +0x72 collision"
                elif op.mem.disp == 0x0C:
                    tags.add('pos0C')
        if '0xcc0b60' in ins.op_str:
            tags.add('eventarr')
        lines.append(f"    0x{ins.address:06X}  {ins.mnemonic:8s} "
                     f"{ins.op_str}{mark}")
    print(f"\n--- +0x61 read at 0x{va:06X}  tags={sorted(tags)} ---")
    for l in lines:
        print(l)

print("\nDone. Look for: the +0x74 read feeding an add with a +0x72 read "
      "(edge-based formula) vs a bare cmp (center formula).")
