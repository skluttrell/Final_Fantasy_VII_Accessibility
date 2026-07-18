#!/usr/bin/env python3
"""
ff7_savefile_preview_derive.py -- Derive the .ff7 save-file slot/preview
layout EMPIRICALLY from the player's own save00.ff7 (2026-07-17).

WHY:
  The save/continue menus (new feature request) must speak each slot's
  preview: lead character, level, play time, gil, location caption -- or
  EMPTY. That data does NOT need memory hunting: the menu renders it from
  the save FILES on disk, which the mod can parse directly. But rather
  than trusting a from-memory recollection of the Qhimm savemap layout,
  this script derives the offsets from ground truth the player just
  provided: their save-menu screenshots (2026-07-17) show slot 1 of
  GAME 01 as Cloud + Barret portraits, "Cloud", Level 7, Time 00:21,
  Gil 376, location "No. 1 Reactor". We search the file for exactly those
  values (location string in FF7 text encoding, gil as u32 = 376, level
  byte 7, name "Cloud") and print every offset relative to the file and
  to the slot base -- the C++ parser is then written against DERIVED
  offsets, not remembered ones.

FF7 PC text encoding (already proven in the mod's FF7Text): printable
ASCII minus 0x20 ('A'=0x21, 'a'=0x41, '0'=0x10, ' '=0x00), 0xFF ends.

EXPECTED SHAPE (to be CONFIRMED here, not assumed): 9-byte file header,
then 15 slots of 0x10F4 bytes each (9 + 15*0x10F4 = 65,109 bytes).
"""
import sys, os, struct, datetime

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"savefile_preview_derive_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore():
    sys.stdout.write = _orig_write
    try: _log_file.close()
    except Exception: pass
atexit.register(_restore)
print(f"Output saving to: {_log_path}\n")

SAVE = r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\save\save00.ff7"

def enc(s):
    """ASCII -> FF7 text bytes."""
    return bytes((ord(c) - 0x20) & 0xFF for c in s)

def dec(b):
    """FF7 text bytes -> ASCII (stop at 0xFF)."""
    out = []
    for c in b:
        if c == 0xFF:
            break
        out.append(chr(c + 0x20) if 0 <= c <= 0x5E else '?')
    return ''.join(out)

data = open(SAVE, 'rb').read()
print(f"File: {SAVE}")
print(f"Size: {len(data):,} bytes")
expect = 9 + 15 * 0x10F4
print(f"Expected 9 + 15*0x10F4 = {expect:,} -> "
      f"{'MATCH' if len(data) == expect else '** MISMATCH -- layout differs **'}")
print(f"Header bytes: {data[:16].hex(' ')}\n")

# -- ground truth from the 2026-07-17 screenshots --------------------------------
LOC   = enc("No. 1 Reactor")
NAME  = enc("Cloud")
GIL   = 376
LEVEL = 7
# Time 00:21 displayed as HH:MM -> 21 minutes; allow 1260..1319 seconds.

print("=== search: location string 'No. 1 Reactor' (FF7-encoded) ===")
loc_hits = []
i = data.find(LOC)
while i != -1:
    loc_hits.append(i)
    i = data.find(LOC, i + 1)
for h in loc_hits:
    print(f"  file offset 0x{h:06X}")
print(f"  {len(loc_hits)} hit(s)\n")

print("=== search: name 'Cloud' (FF7-encoded, 0xFF-padded) ===")
name_hits = []
i = data.find(NAME + b'\xff')
while i != -1:
    name_hits.append(i)
    i = data.find(NAME + b'\xff', i + 1)
for h in name_hits[:20]:
    print(f"  file offset 0x{h:06X}")
print(f"  {len(name_hits)} hit(s)\n")

print("=== search: gil u32 == 376 and seconds u32 in [1260, 1319] ===")
gil_hits, sec_hits = [], []
for off in range(0, len(data) - 4):
    v = struct.unpack_from('<I', data, off)[0]
    if v == GIL:
        gil_hits.append(off)
    if 1260 <= v <= 1319:
        sec_hits.append(off)
print(f"  gil hits: {[hex(h) for h in gil_hits[:20]]} ({len(gil_hits)})")
print(f"  sec hits: {[hex(h) for h in sec_hits[:20]]} ({len(sec_hits)})\n")

# -- interpret: cluster everything around the first slot ------------------------
# If the expected shape holds, slot n starts at 9 + n*0x10F4; the preview
# block should be at the very start of the slot (after its checksum),
# putting all ground-truth hits within the first slot's first ~0x100 bytes.
print("=== slot-relative interpretation (slot base = 9 + n*0x10F4) ===")
def slot_of(off):
    if off < 9:
        return None, off
    n = (off - 9) // 0x10F4
    return n, (off - 9) % 0x10F4

for label, hits in (("location", loc_hits), ("name", name_hits),
                    ("gil", gil_hits), ("seconds", sec_hits)):
    for h in hits[:6]:
        n, rel = slot_of(h)
        print(f"  {label:<9} file 0x{h:06X} = slot {n} + 0x{rel:04X}")
print()

# -- dump the first slot's first 0x80 bytes annotated ---------------------------
print("=== slot 0, first 0x80 bytes (hex + FF7-text) ===")
base = 9
for row in range(0, 0x80, 16):
    chunk = data[base + row: base + row + 16]
    text = ''.join(chr(c + 0x20) if 0 <= c <= 0x5E else '.' for c in chunk)
    print(f"  +0x{row:04X}  {chunk.hex(' ')}  |{text}|")
print()

# -- level byte: expect a 7 at a fixed spot near the preview start --------------
print("=== bytes with value 7 in slot 0 + 0x00..0x60 ===")
for off in range(0x60):
    if data[base + off] == LEVEL:
        print(f"  slot 0 + 0x{off:04X} == 7")
print()

# -- how does an EMPTY slot look? (screenshots show slots 2+ EMPTY) -------------
print("=== slot 1 (EMPTY on screen), first 0x40 bytes ===")
b1 = 9 + 0x10F4
for row in range(0, 0x40, 16):
    chunk = data[b1 + row: b1 + row + 16]
    print(f"  +0x{row:04X}  {chunk.hex(' ')}")
nonzero = sum(1 for c in data[b1: b1 + 0x10F4] if c != 0)
print(f"  nonzero bytes in whole slot 1: {nonzero} of 0x10F4\n")

print(f"Log saved to: {_log_path}")
