#!/usr/bin/env python3
"""
ff7_gkt_section5_callsites_static.py -- find EVERY call site of
get_kernel_text (0x41963C) in ff7_en.exe and decode its argument setup,
2026-08-09.

WHY (tonight's regression, v2.30.101 play log.11): the battle command
menu speaks shifted names -- id 0x01 Attack => "Left", id 0x02 Magic =>
"Attack", id 0x04 Item => "Summon".  CommandMenuName calls
GKT(section 5, id-1) on the v2.30.100 assumption that the command-name
table is 0-based against 1-based command ids (that was true of the
scavenged HEAP section).  The live evidence says the GKT section-5 file
is indexed by the RAW command id (entry 0 holds a "Left" label).  The
[GKT100] verify queue never covered section 5 -- tonight is its first
play exercise.

Before editing the mod, byte-verify from the exe: what index does the
GAME push for section 5 when it draws the command menu?  Method: sweep
.text for the E8 rel32 call to 0x41963C, then disassemble a window
before each site and report the three pushes feeding the __cdecl
(section, idx, arg3) call.  A site pushing section=5 with idx derived
from the command id WITHOUT a -1 adjustment proves the raw-id
convention; any dec/sub before the push proves id-1.

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_gkt_section5_callsites_static.py
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"gkt_section5_callsites_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
]
exe_path = next((c for c in EXE_CANDIDATES if os.path.isfile(c)), None)
if exe_path is None:
    print("ERROR: ff7_en.exe not found")
    sys.exit(1)
data = open(exe_path, 'rb').read()
print(f"Loaded exe: {exe_path} ({len(data)} bytes)")

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    name = data[s:s+8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((name, va, vs, rs, ro))

# .text extent (file offsets) for the call-site sweep
text = next(s for s in secs if s[0] == '.text')
_, tva, tvs, trs, tro = text
text_lo_va = image_base + tva
text_hi_va = text_lo_va + trs

GKT = 0x41963C

# --- sweep for E8 rel32 -> 0x41963C -----------------------------------
sites = []
for off in range(tro, tro + trs - 5):
    if data[off] != 0xE8:
        continue
    rel = struct.unpack_from('<i', data, off + 1)[0]
    src_va = text_lo_va + (off - tro)
    if (src_va + 5 + rel) & 0xFFFFFFFF == GKT:
        sites.append(src_va)
print(f"\ncall 0x{GKT:X} sites in .text: {len(sites)}")
for va in sites:
    print(f"  0x{va:08X}")

# --- decode the argument setup before each site ------------------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def v2o(va):
    r = va - image_base
    for _, sva, svs, srs, sro in secs:
        if sva <= r < sva + max(svs, srs):
            fo = sro + (r - sva)
            return fo if fo < len(data) else None
    return None

WINDOW = 0x60   # bytes of context before the call
for va in sites:
    start = va - WINDOW
    off = v2o(start)
    print()
    print("=" * 76)
    print(f"===== context before call @0x{va:08X}")
    print("=" * 76)
    # capstone linear disasm can start mid-instruction at an arbitrary
    # window edge; restart one byte later until the stream lands exactly
    # on the call address (the project's stops-at-first-bad-byte lesson,
    # applied as alignment search instead).
    for shift in range(0x20):
        insns = [i for i in md.disasm(data[off + shift: off + shift + WINDOW - shift + 5],
                                      start + shift)]
        if any(i.address == va for i in insns):
            for insn in insns:
                if insn.address > va:
                    break
                marker = " <== CALL get_kernel_text" if insn.address == va else ""
                print(f"  0x{insn.address:08X}  {insn.mnemonic:<8s} {insn.op_str}{marker}")
            break
    else:
        print("  !! could not align disassembly window")

print("\nDone.")
