#!/usr/bin/env python3
"""
ff7_solid_modelhit_dump.py -- dump 0x637724, the movement routine's
"does this position hit another model" test, marking STATIC-array
addressing of field_event_data[0] at 0xCC1670 (2026-08-04, pass 6).

WHY: pass 5 showed engine code reads model fields as
[idx*0x88 + 0xCC1670 + off] -- an absolute address per offset -- which
is why the disp-based +0x5F sweep found no reader. The SOLID gate should
appear here as 0xCC16CF (0xCC1670+0x5F). Also sweep ALL of .text for
absolute references to 0xCC16CF to catch every consumer at once.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"solid_modelhit_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

BASE = 0xCC1670
NAMES = {BASE + 0x0C: "pos.x", BASE + 0x10: "pos.y", BASE + 0x14: "pos.z",
         BASE + 0x5D: "+0x5D entity", BASE + 0x5E: "+0x5E",
         BASE + 0x5F: "+0x5F SOLID-OFF", BASE + 0x60: "+0x60",
         BASE + 0x61: "+0x61 talk-off", BASE + 0x62: "+0x62 visible",
         BASE + 0x63: "+0x63 move-type", BASE + 0x6C: "+0x6C char-id",
         BASE + 0x72: "+0x72 radius", BASE + 0x74: "+0x74 talk-r",
         BASE + 0x78: "+0x78 triangle"}

def dump(title, va, end_va):
    print(f"===== {title}: 0x{va:08X} .. 0x{end_va:08X} =====")
    addr = va
    while addr < end_va:
        o = v2o(addr)
        progressed = False
        for ins in md.disasm(data[o:o + (end_va - addr)], addr):
            progressed = True
            note = ""
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.disp in NAMES:
                    note = f"   ; <<< event[i].{NAMES[op.mem.disp]}"
            if ins.mnemonic == 'imul' and '0x88' in ins.op_str:
                note += "   ; stride 0x88"
            print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{note}")
            addr = ins.address + ins.size
            if ins.mnemonic.startswith('ret'):
                addr = end_va
                break
        if not progressed:
            addr += 1
    print()

dump("model-hit test 0x637724", 0x637724, 0x637724 + 0x200)

# All .text references to interesting statics (dword scan)
print("===== .text dword refs to event[0] flag statics =====")
for target, name in ((BASE + 0x5F, "+0x5F SOLID-OFF"),
                     (BASE + 0x5E, "+0x5E"),
                     (BASE + 0x62, "+0x62 visible"),
                     (BASE + 0x72, "+0x72 radius")):
    needle = struct.pack('<I', target)
    pos = -1
    sites = []
    while True:
        pos = data.find(needle, pos + 1, text_ro + text_rs)
        if pos < 0 or pos >= text_ro + text_rs:
            break
        if pos >= text_ro:
            sites.append(o2v(pos))
    print(f"  0x{target:X} ({name}): {[hex(s) for s in sites]}")

print("\nDone.")
