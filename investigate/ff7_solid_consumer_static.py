#!/usr/bin/env python3
"""
ff7_solid_consumer_static.py -- polarity + consumer proof for the SOLID
flag at field_event_data +0x5F (2026-08-04, follow-up to
ff7_solid_static.py which found the store).

QUESTIONS:
  1. POLARITY: the SOLID handler stores the raw script arg. TLKON's
     convention is 0 = enabled, 1 = disabled. Which default do the
     init/bind paths write? ff7_solid_static.py saw 0x60C387 write 0 and
     0x60C928 write 1 -- dump both contexts to see which is the CHAR-bind
     "model starts solid" default (compare against the known CHAR path
     at 0x6143xx that writes +0x62 = 1).
  2. CONSUMER: which routine READS +0x5F to skip a model during
     collision? Sweep .text for readers of the collision radius +0x72
     (word) and dump each candidate function -- the model-vs-model
     collision loop must read the radius, and the SOLID gate should sit
     in the same function. This also reveals the engine's FULL blocking
     predicate (visibility? radius? flag?) so CollectBodies can mirror
     it exactly.

METHOD: exe on disk, capstone with detail; disp-exact operand matching
(the first script's string match caught negative-disp false positives).
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"solid_consumer_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
from capstone import x86

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

def dump(title, va, span=0x100, marks=(0x5F, 0x72, 0x62, 0x61, 0x88)):
    print(f"===== {title} @ 0x{va:08X} (span 0x{span:X}) =====")
    addr, end = va, va + span
    while addr < end:
        o = v2o(addr)
        progressed = False
        for ins in md.disasm(data[o:o + (end - addr)], addr):
            progressed = True
            note = ""
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.disp in marks:
                    note = f"   ; <<< disp +0x{op.mem.disp:X}"
            if ins.mnemonic == 'imul' and '0x88' in ins.op_str:
                note += "   ; stride 0x88 = field_event_data"
            print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{note}")
            addr = ins.address + ins.size
            if ins.mnemonic.startswith('ret'):
                addr = end
                break
        if not progressed:
            addr += 1
    print()

# ---- Q1: the two default writers' context -----------------------------------
dump("+0x5F := 0 writer context (0x60C387 - 0x60)", 0x60C387 - 0x60, 0xB0)
dump("+0x5F := 1 writer context (0x60C928 - 0x60)", 0x60C928 - 0x60, 0xB0)
# The known CHAR-bind visible=1 store sits at 0x6143D2; dump the CHAR
# handler region to see whether it also initializes +0x5F.
dump("CHAR bind region (0x614390)", 0x614390, 0xA0)

# ---- Q2: find +0x72 radius READERS (word width, exact disp) -----------------
print("===== .text sweep: mem operands with disp == +0x72 (any width) =====")
hits = []
o = text_ro
end_o = text_ro + text_rs
while o < end_o - 12:
    b = data[o]
    # candidate first bytes for mov/movsx/movzx/cmp/test/arith with modrm
    if b in (0x0F, 0x66, 0x8B, 0x8A, 0x89, 0x88, 0x3B, 0x39, 0x66,
             0xF6, 0xF7, 0x80, 0x81, 0x83, 0xC6, 0xC7):
        va = o2v(o)
        ins = next(iter(md.disasm(data[o:o + 12], va)), None)
        if ins:
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.disp == 0x72 and \
                        (op.mem.base != 0 or op.mem.index != 0):
                    hits.append((va, f"{ins.mnemonic} {ins.op_str}"))
                    break
    o += 1
seen = set()
for va, txt in hits:
    if va in seen:
        continue
    seen.add(va)
    tag = " <-- field engine range" if 0x5F0000 <= va - image_base + image_base \
        and 0x600000 <= va <= 0x660000 else ""
    print(f"  0x{va:X}: {txt}{tag}")

# ---- Q2b: exact-disp +0x5F readers (re-run of pass 1 without string bugs) ---
print("\n===== .text sweep: mem operands with disp == +0x5F (any width) =====")
o = text_ro
hits5f = []
while o < end_o - 12:
    b = data[o]
    if b in (0x0F, 0x66, 0x8B, 0x8A, 0x89, 0x88, 0x3B, 0x39,
             0xF6, 0xF7, 0x80, 0x81, 0x83, 0xC6, 0xC7, 0x38, 0x3A):
        va = o2v(o)
        ins = next(iter(md.disasm(data[o:o + 12], va)), None)
        if ins:
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.disp == 0x5F and \
                        (op.mem.base != 0 or op.mem.index != 0):
                    is_store = (op is ins.operands[0] and
                                ins.mnemonic in ('mov', 'or', 'and', 'xor'))
                    hits5f.append((va, is_store,
                                   f"{ins.mnemonic} {ins.op_str}"))
                    break
    o += 1
seen = set()
for va, w, txt in hits5f:
    if va in seen:
        continue
    seen.add(va)
    tag = " <-- field engine range" if 0x600000 <= va <= 0x660000 else ""
    print(f"  0x{va:X} [{'WRITE' if w else 'read '}]: {txt}{tag}")

print("\nDone.")
