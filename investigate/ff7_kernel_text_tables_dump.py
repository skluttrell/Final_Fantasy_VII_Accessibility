#!/usr/bin/env python3
"""
ff7_kernel_text_tables_dump.py -- decode KERNEL.BIN's text pieces with
EXPLICIT entry indexing, 2026-08-09.

WHY (v2.30.102 postmortem): the .100 rework shipped GKT section 5 with a
GUESSED index convention (id-1) because "what does entry N of the
command-names file hold" had never been answered from the actual data --
every earlier dump (kernel2_section_enum) located sections by SIGNATURE
heuristics, which hides exactly the alignment question that mattered
(the file's filler entry 0). This script is the prevention: it parses
KERNEL.BIN's gzip container directly -- piece numbers and entry indices
are POSITIONAL, no signatures anywhere -- so any future "which entry
does id N hit" question is answered in seconds, offline, before code
ships.

GKT correspondence (byte-verified v2.30.100/.102, research S4
GET_KERNEL_TEXT row): kernel2_get_text file index f = 1-based KERNEL.BIN
piece (f + 10); every engine call site passes file_base 8, so
    GKT section 0..3 -> file 9  -> piece 19 (magic names, biased)
    GKT section 4    -> file 10 -> piece 20 (item names, remapped)
    GKT section 5    -> file 8  -> piece 18 (command names, RAW id)

NOTE: on 2013+7H the RUNTIME text comes from the IRO (Echo-S), not this
disk file -- this dump answers LAYOUT/convention questions (entry
counts, filler entries, index alignment), which are shared by every
rebuild that renders correctly through the engine's own draw calls; it
does not predict retranslated content.

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_kernel_text_tables_dump.py
"""
import sys, os, struct, zlib, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel_text_tables_dump_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

CANDIDATES = [
    ("2013", r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\lang-en\kernel\KERNEL.BIN"),
    ("2026", r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\lang-en\kernel\KERNEL.BIN"),
]

# Text pieces worth dumping (1-based piece number -> label). 18-25 are the
# name files GKT can serve (directly or via the section-4 remap); 10 is
# the command DESCRIPTION sibling -- the file whose visible entry-0
# duplication first evidenced the filler-entry-0 layout.
PIECES = {
    10: "command descriptions",
    18: "command names   (GKT section 5, RAW-id-indexed)",
    19: "magic names     (GKT sections 0-3 via bias 0/56/72/128)",
    20: "item names      (GKT section 4, remap target 'items')",
    21: "weapon names    (section-4 remap, idx 0x80-0xFF)",
    22: "armor names     (section-4 remap, idx 0x100-0x11F)",
    23: "accessory names (section-4 remap, idx 0x120-0x17F)",
}

# Minimal FF7 text decode -- enough to read names: the printable range is
# a flat +0x20 ASCII offset; everything else prints as \xNN so nothing is
# silently mis-rendered (this is a layout tool, not a translator).
def decode(b):
    out = []
    for c in b:
        if c == 0xFF:
            break
        if c < 0x60:
            out.append(chr(c + 0x20))
        else:
            out.append(f"\\x{c:02X}")
    return "".join(out)

def dump_kernel(tag, path):
    print("=" * 76)
    print(f"===== {tag}: {path}")
    print("=" * 76)
    if not os.path.isfile(path):
        print("  (missing -- skipped)\n")
        return
    data = open(path, 'rb').read()
    print(f"  {len(data)} bytes")
    # KERNEL.BIN = concatenated pieces, each: u16 csize, u16 usize,
    # u16 file_type, then csize bytes of gzip data.
    pieces, off = [], 0
    while off + 6 <= len(data):
        csize, usize, ftype = struct.unpack_from('<3H', data, off)
        if csize == 0:
            break
        blob = data[off + 6: off + 6 + csize]
        try:
            raw = zlib.decompress(blob, 15 + 32)
        except Exception as e:
            raw = None
            print(f"  piece {len(pieces)+1}: DECOMPRESS FAILED ({e})")
        pieces.append((ftype, usize, raw))
        off += 6 + csize
    print(f"  {len(pieces)} pieces\n")

    for num, label in sorted(PIECES.items()):
        if num > len(pieces):
            print(f"-- piece {num} ({label}): MISSING")
            continue
        ftype, usize, raw = pieces[num - 1]
        print(f"-- piece {num} ({label}): type={ftype} {len(raw) if raw else 0} bytes")
        if raw is None:
            continue
        # Text piece = u16 offset table then FF-terminated strings; the
        # entry count is offsets[0]/2 (first string starts right after
        # the table).  Same structure kernel2_get_text walks at runtime.
        first = struct.unpack_from('<H', raw, 0)[0]
        count = first // 2
        print(f"   entry count = {count} (offset-table extent {first})")
        for i in range(count):
            o = struct.unpack_from('<H', raw, i * 2)[0]
            print(f"   [{i:3d}] +0x{o:04X} '{decode(raw[o:o+48])}'")
        # The convention check that was missing before v2.30.102:
        if num == 18:
            e0 = struct.unpack_from('<H', raw, 0)[0]
            e1 = struct.unpack_from('<H', raw, 2)[0] if count > 1 else e0
            same = decode(raw[e0:e0+32]) == decode(raw[e1:e1+32])
            print(f"   >>> entry0 == entry1 (filler duplication): {same}"
                  f" -- raw command id indexes this table (engine draw"
                  f" 0x71F35A pushes it unadjusted)")
        print()

for tag, path in CANDIDATES:
    dump_kernel(tag, path)

print("Done.")
