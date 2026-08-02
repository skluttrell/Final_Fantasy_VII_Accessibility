#!/usr/bin/env python3
"""
ff7_ladder_static.py -- what the LADER opcode sets, so the mod can tell a
player they are ON a ladder and which way to push (2026-08-02).

Tester report: "difficulty knowing when they are on or off a ladder and
what direction to push."

KNOWN going in (v2.17 bonus find, research §4/§14): the LADER handler is
execute_opcode_table[0xC2] = 0x615EC6; it writes field_event_data +0x63
(movement type/phase) and +0x7C/+0x80/+0x84 (movement target, <<12), and
reads an anim-data pointer 0xCFF738 (stride 0x190).

WHAT THIS ADDS -- the parts the mod needs and must NOT guess:
  1. the exact VALUE(s) written to +0x63 (the "climbing" state the mod
     will poll to say "on ladder" / "off ladder"),
  2. which script argument becomes the target position (so the push
     direction can be derived as target-minus-current, then rotated by
     control_direction like every other spoken direction), and
  3. whether a direction/animation argument is stored anywhere readable
     (a ladder's own up/down orientation).
  4. who else writes +0x63 -- if ordinary walking uses the same byte,
     the mod needs the specific climb value, not "nonzero".

METHOD: exe on disk (file VAs == runtime VAs), locate the opcode table
via the documented IDLCK anchor, disassemble the handler, then sweep
.text for every other instruction that writes +0x63 through the
field_event_data base pattern (imul 0x88 / [0xCC0B60]).
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"ladder_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
h_lader = struct.unpack_from('<I', data, t_off + 0xC2 * 4)[0]
print(f"opcode table @ 0x{o2v(t_off):X}")
print(f"  [0xC2] LADER = 0x{h_lader:08X}\n")

print("===== LADER handler disassembly =====")
addr, end = h_lader, h_lader + 0x300
writes63 = []
while addr < end:
    o = v2o(addr)
    progressed = False
    for ins in md.disasm(data[o:o + (end - addr)], addr):
        progressed = True
        note = ""
        op_str = ins.op_str
        if '0x63' in op_str and '[' in op_str:
            note = "   ; <<< +0x63 movement type"
            writes63.append((ins.address, f"{ins.mnemonic} {op_str}"))
        for off_name, off in (("+0x7C", '0x7c'), ("+0x80", '0x80'),
                              ("+0x84", '0x84'), ("stride", '0x88')):
            if off in op_str:
                note += f"   ; {off_name}"
        print(f"  0x{ins.address:X}: {ins.mnemonic} {op_str}{note}")
        addr = ins.address + ins.size
        if ins.mnemonic.startswith('ret'):
            addr = end
            break
    if not progressed:
        addr += 1

print("\n===== +0x63 writes inside LADER =====")
for a, t in writes63:
    print(f"  0x{a:X}: {t}")

# Every other site in .text that touches a [..+0x63] byte through a
# 0x88-strided base -- i.e. other writers of the same field.
print("\n===== other +0x63 sites in .text (mov byte ptr [reg+reg+0x63]) =====")
count = 0
o = text_ro
end_o = text_ro + text_rs
while o < end_o - 8:
    # quick byte filter: 'mov byte ptr [x+y+0x63], imm8' encodings start C6 44 / 88
    if data[o] in (0xC6, 0x88, 0x8A):
        va = o2v(o)
        ins = next(iter(md.disasm(data[o:o + 8], va)), None)
        if ins and '0x63]' in ins.op_str:
            acc = 'WRITE' if ins.mnemonic == 'mov' and ins.op_str.strip().startswith('byte ptr') else 'read'
            print(f"  0x{va:X} [{acc}]: {ins.mnemonic} {ins.op_str}")
            count += 1
            if count > 40:
                print("  ... (truncated)")
                break
    o += 1
print("\nDone.")
