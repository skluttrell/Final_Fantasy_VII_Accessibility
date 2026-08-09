#!/usr/bin/env python3
"""
ff7_battle_miss_static5.py -- fifth (final) pass: sentinel semantics.

Pass 4 found the damage-event record ALLOCATOR at 0x436DA7:
  idx = [0x9AEA98] (u32 ring counter & 0x7F -> 128 records)
  rec = 0x9ABA08 + idx*0xE   (battle-init memset 0x1C0 dwords = 128*14)
  anim_event->byte[3] = idx;  rec+0 = anim_event actor byte;
  rec+6 = rec+8 = 0xFFFF (barrier/m-barrier gauge defaults, consumed
  by 0x4371FC into the party HUD gauge words 0x9A8B4C/0x9A8B4E);
  returns rec in eax.
Record: +2 = HP display value (-1/-2/-3 = glyphs, else digits),
        +4 = flags word, +0xA = MP display value, +0xC = MP flags.

The damage calc holds the returned pointer and writes fields
REGISTER-RELATIVE -- invisible to constant sweeps. So: find every
`call 0x436DA7` site (and the 0x436DFF wrapper's callers too), then
disassemble a generous window AFTER each call to catch the
`mov word [reg+2], imm` stores and their guarding branches. The
conditions around a store of 0xFFFF (vs 0xFFFE/0xFFFD) are the game
meaning of each glyph -- the deliverable of this pass.
"""
import sys, os, struct, datetime
import capstone

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_miss_static5_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
_log = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s)
    _log.write(s)
    _log.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

def find_exe():
    for cand in (
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    ):
        if os.path.isfile(cand):
            return cand
    raise RuntimeError("exe not found")

exe_path = find_exe()
print(f"exe: {exe_path}")
with open(exe_path, 'rb') as f:
    data = f.read()
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
coff = e_lfanew + 4
nsec = struct.unpack_from('<HH', data, coff)[1]
optsz = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
base = struct.unpack_from('<I', data, opt + 28)[0]
secoff = opt + optsz
secs = []
text_lo = text_hi = text_rp = None
for i in range(nsec):
    o = secoff + i * 40
    name = data[o:o + 8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', data, o + 8)
    secs.append((va, vs, rp))
    if name == '.text':
        text_lo, text_hi, text_rp = base + va, base + va + vs, rp

def v2o(va):
    r = va - base
    for sva, svs, srp in secs:
        if sva <= r < sva + svs:
            return srp + (r - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def find_callers(target):
    """Every E8 rel32 site in .text whose destination == target."""
    hits = []
    off = text_rp
    size = text_hi - text_lo
    i = data.find(b'\xE8', off, off + size)
    while i != -1:
        rel = struct.unpack_from('<i', data, i + 1)[0]
        va = text_lo + (i - text_rp)
        if (va + 5 + rel) == target:
            hits.append(va)
        i = data.find(b'\xE8', i + 1, off + size)
    return hits

def dump_around(label, call_va, before=0x30, after=0x1C0):
    start = call_va - before
    off = v2o(start)
    if off is None:
        return
    print("=" * 70)
    print(f"{label}: call at 0x{call_va:X}")
    print("=" * 70)
    for insn in md.disasm(data[off:off + before + after], start):
        if insn.id == 0:
            continue
        tag = "  <== CALL" if insn.address == call_va else ""
        # Flag the sentinel stores loudly so the log is scannable.
        if insn.mnemonic == 'mov' and ', 0xfff' in insn.op_str:
            tag += "   <<< SENTINEL STORE"
        print(f"  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}{tag}")
    print()

for target, name in ((0x436DA7, "alloc_damage_event_0x436DA7"),
                     (0x436DFF, "wrapper_0x436DFF")):
    callers = find_callers(target)
    print(f"### {name}: {len(callers)} call sites: "
          f"{', '.join('0x%X' % c for c in callers)}\n")
    for c in callers:
        dump_around(name, c)
print("DONE.")
