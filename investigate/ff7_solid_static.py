#!/usr/bin/env python3
"""
ff7_solid_static.py -- what the SOLID opcode sets, so the pathfinder can
stop treating script-intangible people as blockers (2026-08-04).

Tester report: the pathfinder says characters are blocking paths even when
they are intangible -- e.g. the unconscious guard bodies on the Sector 1
station platform at the start of the Reactor mission, which the player
walks straight through in-game.

KNOWN going in:
  - CollectBodies() (proxy.cpp) treats FIELD_EVENT_COLLISION_RADIUS
    (+0x72, SLIDR family) <= 0 as the ONLY intangibility signal.
  - The field script ALSO has a SOLID opcode (0xC7 in the standard
    opcode list: ...0xC5 TALKR, 0xC6 SLIDR, 0xC7 SOLID...) that toggles
    collision WITHOUT touching the radius -- the suspected mechanism for
    walk-through bodies. Its stored flag offset is unmapped.
  - Sibling toggles already mapped from this exact handler cluster:
    TLKON 0x7E -> +0x61 (raw arg, 1 = disabled), VISI 0xA4 -> +0x62.
    SOLID plausibly stores its raw arg to a neighboring byte.

WHAT THIS ANSWERS -- the parts the mod must NOT guess:
  1. the exact struct offset the SOLID handler writes, and whether the
     script arg is stored raw (TLKON-style: 0 = solid, 1 = intangible)
     or inverted;
  2. cross-check: TALKR/SLIDR handlers must write +0x74/+0x72 -- if they
     do, the same decode applied to SOLID is trustworthy;
  3. who READS the flag -- the engine's own model-collision routine.
     Finding a reader next to a +0x72 (radius) read is the cross-proof
     that this byte gates blocking, and shows the engine's full
     predicate so the mod can mirror it exactly.

METHOD: exe on disk (file VAs == runtime VAs), locate the opcode table
via the documented IDLCK anchor (ff7_ladder_static.py recipe verbatim),
disassemble handlers 0x7E/0xC5/0xC6/0xC7, then sweep .text for every
instruction touching the discovered offset through the field_event_data
addressing pattern.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"solid_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

exe = next(c for c in (
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
) if os.path.isfile(c))
print(f"Reading: {exe}")
data = open(exe, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((va, vs, ro, rs))
text_va, text_vs, text_ro, text_rs = secs[0]

def v2o(va):
    r = va - image_base
    for sva, svs, sro, srs in secs:
        if sva <= r < sva + max(svs, srs):
            return sro + (r - sva)
    return None
def o2v(off):
    for sva, svs, sro, srs in secs:
        if sro <= off < sro + srs:
            return image_base + sva + (off - sro)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# -- Step 1: opcode table via the IDLCK anchor (ladder-script recipe) ----------
IDLCK = 0x0061E29F
needle = struct.pack('<I', IDLCK)
pos, t_off = -1, None
while True:
    pos = data.find(needle, pos + 1)
    if pos < 0:
        break
    cand = pos - 0x6D * 4
    if cand >= 0 and all(
            image_base <= struct.unpack_from('<I', data, cand + k * 4)[0]
            < image_base + 0x00A00000 for k in range(256)):
        t_off = cand
        break
assert t_off is not None, "opcode table not found"
def handler(op):
    return struct.unpack_from('<I', data, t_off + op * 4)[0]

print(f"opcode table @ 0x{o2v(t_off):X}")
h_tlkon = handler(0x7E)
h_talkr = handler(0xC5)
h_slidr = handler(0xC6)
h_solid = handler(0xC7)
print(f"  [0x7E] TLKON = 0x{h_tlkon:08X}  (expect 0x00618A80 -- validation)")
print(f"  [0xC5] TALKR = 0x{h_talkr:08X}  (expect a +0x74 write)")
print(f"  [0xC6] SLIDR = 0x{h_slidr:08X}  (expect a +0x72 write)")
print(f"  [0xC7] SOLID = 0x{h_solid:08X}  (the unknown)\n")
assert h_tlkon == 0x00618A80, "TLKON mismatch -- table decode is WRONG, stop"

# -- Step 2: disassemble each handler, note struct-offset stores ---------------
def dump(name, va, span=0x120):
    print(f"===== {name} @ 0x{va:08X} =====")
    stores = []
    addr, end = va, va + span
    while addr < end:
        o = v2o(addr)
        progressed = False
        for ins in md.disasm(data[o:o + (end - addr)], addr):
            progressed = True
            note = ""
            # any memory operand with a disp in the struct's range is
            # interesting; stores are the answer
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and \
                        0x40 <= op.mem.disp <= 0x87 and \
                        (op.mem.base != 0 or op.mem.index != 0):
                    rw = 'WRITE' if ins.operands[0] is op else 'read'
                    note = f"   ; <<< [{rw}] struct +0x{op.mem.disp:X}"
                    if rw == 'WRITE':
                        stores.append((ins.address, op.mem.disp,
                                       f"{ins.mnemonic} {ins.op_str}"))
            print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{note}")
            addr = ins.address + ins.size
            if ins.mnemonic.startswith('ret'):
                addr = end
                break
        if not progressed:
            addr += 1
    print()
    return stores

dump("TLKON handler (known-good reference)", h_tlkon)
dump("TALKR handler", h_talkr)
dump("SLIDR handler", h_slidr)
solid_stores = dump("SOLID handler", h_solid, span=0x160)

print("===== SOLID handler struct stores =====")
for a, disp, t in solid_stores:
    print(f"  0x{a:X}: +0x{disp:X}  {t}")
if not solid_stores:
    print("  NONE FOUND -- widen the span / check addressing pattern")
    sys.exit(1)

# -- Step 3: sweep .text for every toucher of the discovered offset(s) ---------
# Same quick-filter trick as the ladder script: mov-family opcode bytes,
# then let capstone decide. Reports both reads and writes -- a READ in a
# collision-shaped routine (near +0x72 radius use) is the consumer proof.
offsets = sorted({disp for _, disp, _ in solid_stores})
for target in offsets:
    print(f"\n===== .text sweep: [reg...+0x{target:X}] byte accesses =====")
    count = 0
    o = text_ro
    end_o = text_ro + text_rs
    pat = f'0x{target:x}]'
    while o < end_o - 10:
        if data[o] in (0xC6, 0x88, 0x8A, 0x80, 0xF6, 0x0F, 0x38, 0x3A):
            va = o2v(o)
            ins = next(iter(md.disasm(data[o:o + 10], va)), None)
            if ins and pat in ins.op_str and 'byte ptr' in ins.op_str:
                # classify: first operand memory = write (mov/imm store)
                is_write = (ins.mnemonic == 'mov' and
                            ins.op_str.strip().startswith('byte ptr'))
                print(f"  0x{va:X} [{'WRITE' if is_write else 'read '}]: "
                      f"{ins.mnemonic} {ins.op_str}")
                count += 1
                if count > 60:
                    print("  ... (truncated)")
                    break
        o += 1
    if count == 0:
        print("  (no byte-width touchers -- try word width manually)")

print("\nDone.")
