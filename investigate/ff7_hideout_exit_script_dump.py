#!/usr/bin/env python3
"""
ff7_hideout_exit_script_dump.py -- What do the hideout's line triggers DO?
(2026-07-25 play question: "I think I am supposed to go back up stairs...
there is a 'border' in the triggers section, but I can't seem to do
anything," standing ON the line at dist 3.)

Field mds7pb_2 (id 155) has three LINE triggers (live log):
  ent=8  'pinball' (155,-14)-(129,-65)   <- where the lift landed us at 11:04
  ent=9  'border'  (56,214)-(-32,123)    <- where the player is standing now
  ent=10 'TV'      (79,156)-(103,108)

This script parses field-file section 0 (script) and dumps, per line
entity: the 32 script entry offsets and a byte dump of each distinct
script, annotated with the opcodes that matter for "how do I leave":
  0x60 MAPJUMP (u16 field + s16 x,y + u16 tri + u8 dir) -> a field exit
  0x5F/0x0F.. (not decoded -- raw hex is printed for hand-reading)
Also greps ALL entity scripts for MAPJUMP with a plausible field id, so
the exit path is found even if it lives in another entity (a lift
entity, an 'ev' door entity...).

Script section layout (community-documented, validated by this project's
entity-name reads at +0x20 + id*8 -- research doc "script entity names"):
  +0x00 u16 unknown, +0x02 u8 nEntities, +0x03 u8 nModels,
  +0x04 u16 wStringOffset, +0x06 u16 nAkaoOffsets, +0x08 u16 scale,
  +0x0A u8[6], +0x10 char[8] creator, +0x18 char[8] field name,
  +0x20 char[8] x nEntities entity names,
  then u32 x nAkaoOffsets, then per entity 32 x u16 script entry offsets
  (relative to the SCRIPT SECTION start, i.e. the u16-table base).
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"hideout_exit_script_dump_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

FIELD = "mds7pb_2"
LINE_ENTS = (8, 9, 10)

CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp_path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not lgp_path:
    print("ERROR: flevel.lgp not found")
    sys.exit(1)
data = open(lgp_path, 'rb').read()
n_files = struct.unpack_from('<I', data, 12)[0]
entry_off = None
for i in range(n_files):
    off = 16 + i * 27
    if data[off:off + 20].split(b'\0')[0].decode('ascii', 'replace').lower() == FIELD:
        entry_off = struct.unpack_from('<I', data, off + 20)[0]
        break
if entry_off is None:
    print(f"ERROR: {FIELD} not in TOC")
    sys.exit(1)

def lzs_decompress(src, max_out):
    out = bytearray()
    win = bytearray(4096)
    wpos = 0xFEE
    i, n = 0, len(src)
    while i < n and len(out) < max_out:
        ctrl = src[i]; i += 1
        for bit in range(8):
            if len(out) >= max_out or i >= n:
                break
            if ctrl & (1 << bit):
                b = src[i]; i += 1
                out.append(b)
                win[wpos] = b
                wpos = (wpos + 1) & 0xFFF
            else:
                if i + 1 >= n:
                    i = n; break
                b1, b2 = src[i], src[i + 1]; i += 2
                pos = b1 | ((b2 & 0xF0) << 4)
                length = (b2 & 0x0F) + 3
                for k in range(length):
                    b = win[(pos + k) & 0xFFF]
                    out.append(b)
                    win[wpos] = b
                    wpos = (wpos + 1) & 0xFFF
                    if len(out) >= max_out:
                        break
    return bytes(out)

flen = struct.unpack_from('<I', data, entry_off + 20)[0]
dec = lzs_decompress(data[entry_off + 24:entry_off + 24 + flen][4:], 4 * 1024 * 1024)
sec_offs = struct.unpack_from('<9I', dec, 6)
sc = sec_offs[0] + 4                 # script section payload (skip u32 size)
sc_end = sec_offs[1]
n_ent = dec[sc + 2]
n_akao = struct.unpack_from('<H', dec, sc + 6)[0]
print(f"{FIELD}: script at 0x{sc:X}..0x{sc_end:X}, {n_ent} entities, "
      f"{n_akao} akao offsets")

names = []
for e in range(n_ent):
    nm = dec[sc + 0x20 + e * 8: sc + 0x20 + (e + 1) * 8].split(b'\0')[0]
    names.append(nm.decode('ascii', 'replace'))
print("entities:", {i: n for i, n in enumerate(names)})

tab = sc + 0x20 + n_ent * 8 + n_akao * 4
def script_offsets(e):
    return [struct.unpack_from('<H', dec, tab + (e * 32 + s) * 2)[0]
            for s in range(32)]

# Bound each entity's script region: from its first entry to the next
# entity's first entry (last entity: to wStringOffset).
firsts = [min(script_offsets(e)) for e in range(n_ent)]
wstr = struct.unpack_from('<H', dec, sc + 4)[0]
bounds = firsts + [wstr]

def find_mapjumps(lo, hi):
    """Scan a script byte range for plausible MAPJUMP (0x60): u16 field id
    < 800, plausible coords. Byte-scan, so treat hits as leads."""
    hits = []
    p = lo
    while p + 10 <= hi:
        if dec[sc + p] == 0x60:
            fid, x, y, tri, d = struct.unpack_from('<Hhh Hb'.replace(' ', ''),
                                                   dec, sc + p + 1)
            if fid < 800:
                hits.append((p, fid, x, y, tri, d))
        p += 1
    return hits

print("\n=== per-entity script table (line entities + neighbors) ===")
for e in range(n_ent):
    offs = script_offsets(e)
    uniq = sorted(set(offs))
    lo, hi = firsts[e], bounds[e + 1]
    mj = find_mapjumps(lo, hi)
    mark = "  <== LINE" if e in LINE_ENTS else ""
    print(f"\nentity {e} '{names[e]}'{mark}  region 0x{lo:X}..0x{hi:X}")
    print(f"  entry offsets: {['0x%X' % o for o in uniq]}")
    print(f"  slot map: " + " ".join(f"s{s}=0x{offs[s]:X}"
                                     for s in range(8)))
    if mj:
        for (p, fid, x, y, tri, d) in mj:
            print(f"  MAPJUMP? @+0x{p:X}: field={fid} pos=({x},{y}) "
                  f"tri={tri} dir={d}")
    if e in LINE_ENTS:
        for o in uniq:
            end = min(o + 96, hi)
            hx = ' '.join(f"{dec[sc + q]:02X}" for q in range(o, end))
            print(f"  script @0x{o:X}: {hx}")

print("\nDone.")
