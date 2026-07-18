#!/usr/bin/env python3
"""
ff7_short_entity_context.py -- Per-field entity-name context for the short
cryptic dev names the user still hears in the Triggers browser ("ev", "dr",
"jp", "sp", ...), 2026-07-17.

WHY:
  The v2.20 translation tables were built from the game-wide stem catalog
  (flevel_entity_names_20260715_122652.log), but that log only prints
  aggregate stem counts with up to 6 sample fields.  To translate a
  two-letter stem safely we need the FULL entity list of each field where
  it occurs -- the neighbouring names are the evidence (e.g. if jail2 has
  "sp" but NO other save-named entity while its model list has the
  save-icon .char, then "sp" is that field's save-point entity).  Per the
  project rule: a wrong translation is worse than a terse one, so every
  new table entry must be grounded this way.

HOW:
  Same LGP walk + LZS early-stop + section-0 header parse as
  ff7_flevel_entity_names_catalog.py (see that file for the format
  documentation).  For each target stem we print every field that contains
  it together with that field's complete entity list.
"""
import sys, os, struct, datetime
from collections import defaultdict

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"short_entity_context_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp_path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not lgp_path:
    print("ERROR: flevel.lgp not found.")
    sys.exit(1)
data = open(lgp_path, 'rb').read()
n_files = struct.unpack_from('<I', data, 12)[0]
toc = []
for i in range(n_files):
    off = 16 + i * 27
    raw_name = data[off:off + 20].split(b'\0')[0]
    file_off = struct.unpack_from('<I', data, off + 20)[0]
    toc.append((raw_name.decode('ascii', 'replace').lower(), file_off))

def lzs_decompress(src, max_out):
    out = bytearray(); win = bytearray(4096); wpos = 0xFEE
    i, n = 0, len(src)
    while i < n and len(out) < max_out:
        ctrl = src[i]; i += 1
        for bit in range(8):
            if len(out) >= max_out or i >= n:
                break
            if ctrl & (1 << bit):
                b = src[i]; i += 1
                out.append(b); win[wpos] = b; wpos = (wpos + 1) & 0xFFF
            else:
                if i + 1 >= n:
                    i = n; break
                b1, b2 = src[i], src[i + 1]; i += 2
                pos = b1 | ((b2 & 0xF0) << 4); length = (b2 & 0x0F) + 3
                for k in range(length):
                    b = win[(pos + k) & 0xFFF]
                    out.append(b); win[wpos] = b; wpos = (wpos + 1) & 0xFFF
                    if len(out) >= max_out:
                        break
    return bytes(out)

def parse_entity_names(payload):
    head = lzs_decompress(payload, 64)
    if len(head) < 6 + 9 * 4:
        return None
    offs = struct.unpack_from('<9I', head, 6)
    if any(offs[i] >= offs[i + 1] for i in range(8)):
        return None
    if offs[0] < 6 or offs[8] > 0x400000:
        return None
    sec_off = offs[0]
    need = sec_off + 4 + 0x20 + 128 * 8
    buf = lzs_decompress(payload, need)
    if len(buf) < sec_off + 4 + 0x20:
        return None
    p = sec_off + 4
    n_entities = buf[p + 2]
    if n_entities == 0 or n_entities > 128:
        return None
    names_off = p + 0x20
    if names_off + n_entities * 8 > len(buf):
        return None
    names = []
    for e in range(n_entities):
        raw = buf[names_off + e * 8: names_off + e * 8 + 8].split(b'\0')[0]
        if any(c < 0x20 or c > 0x7E for c in raw):
            return None
        names.append(raw.decode('ascii').lower().replace('_', ' ').strip())
    return names

def stem(nm):
    s = nm.rstrip('0123456789 ')
    return s if s else nm

# The stems under investigation: the four the user reported plus the other
# short/cryptic high-frequency stems from the game-wide catalog that the
# v2.20 tables do not translate yet.
TARGETS = {'ev', 'dr', 'jp', 'sp', 'ad', 'cl', 'ti', 'ba', 'ea', 're',
           'vin', 'yuf', 'ket', 'dic', 'mes', 'tv', 'jl', 'ln', 'll',
           'se', 'lg', 'mat', 'mate', 'dr an', 'cl a', 'cl hei'}

field_entities = {}
for fname, foff in toc:
    dlen = struct.unpack_from('<I', data, foff + 20)[0]
    body = data[foff + 24: foff + 24 + dlen]
    if len(body) < 8:
        continue
    lzs_size = struct.unpack_from('<I', body, 0)[0]
    if lzs_size + 4 != len(body):
        continue
    names = parse_entity_names(body[4:])
    if names:
        field_entities[fname] = names

print(f"Parsed {len(field_entities)} fields.\n")

hits = defaultdict(list)
for fname, names in field_entities.items():
    stems_here = {stem(nm) for nm in names}
    for t in TARGETS:
        if t in stems_here:
            hits[t].append(fname)

for t in sorted(TARGETS):
    fields = sorted(hits.get(t, []))
    print(f"=== stem '{t}' -- {len(fields)} field(s) ===")
    # Print the complete entity list for up to 8 fields; the surrounding
    # names are the identification evidence.
    for f in fields[:8]:
        print(f"  {f:<12} {field_entities[f]}")
    if len(fields) > 8:
        print(f"  ... and {len(fields) - 8} more: {','.join(fields[8:20])}")
    print()

print(f"Log saved to: {_log_path}")
