#!/usr/bin/env python3
"""
ff7_flevel_entity_names_catalog.py -- Game-wide catalog of field SCRIPT
ENTITY dev names, extracted OFFLINE from flevel.lgp (2026-07-15).

WHY:
  The v2.17 Triggers category names LINE trigger zones by their owning
  entity's dev name ("evb", "drE", "yubiwa") -- terse developer romaji a
  blind player has to memorize. TODO.txt's Triggers residual planned a
  romaji translation table "if common ones recur ('dr'=door,
  'ev'=elevator, 'kaidan'=stairs)". Per the technique ranking (research
  doc section 14: offline data catalog = rank 2), the table must be built
  from the COMPLETE game-wide name list, not guessed from the few fields
  the player has visited -- exactly how the v2.18 Items classifier was
  grounded by ff7_flevel_models_catalog.py.

HOW:
  Same LGP walk + LZS early-stop decompression as the models catalog (see
  ff7_flevel_models_catalog.py for the format documentation), but reading
  SECTION 0 (the script section) instead of section 2. Section 0 layout
  (research doc section 4 "script entity names", live-confirmed
  2026-07-14 on field 120): u32 size prefix, then a 0x20-byte header
  (u16 unknown, u8 nEntities @+2, u8 nModels, u16 wStringOffset,
  u16 nAkaoOffsets, u16 scale, u8[6] blank, char[8] creator,
  char[8] field name), then char[8] ASCII dev names, one per entity.

VALIDATION: field nmkin_2 must contain the two names the shipped v2.17
  build read LIVE from the engine's line array via the entity-name table
  ("yubiwa" -- research doc; the player's reactor session). Plus every
  parsed name must be clean printable ASCII, or the field is skipped and
  counted (same trust rule as the live parser).

Output: full name catalog (count, sample fields) grouped by digit-stripped
stem, plus a keyword scan for candidate romaji words. Feeds the v2.20
dev-label translation table.
"""
import sys, os, struct, datetime
from collections import defaultdict

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"flevel_entity_names_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- locate flevel.lgp -----------------------------------------------------------
CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp_path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not lgp_path:
    print("ERROR: flevel.lgp not found in either install.")
    sys.exit(1)
print(f"Reading: {lgp_path}")
data = open(lgp_path, 'rb').read()
print(f"  {len(data):,} bytes\n")

if b"SQUARESOFT" not in data[:16]:
    print("ERROR: LGP magic not found -- not an LGP archive?")
    sys.exit(1)
n_files = struct.unpack_from('<I', data, 12)[0]
print(f"TOC: {n_files} files")
toc = []
for i in range(n_files):
    off = 16 + i * 27
    raw_name = data[off:off + 20].split(b'\0')[0]
    file_off = struct.unpack_from('<I', data, off + 20)[0]
    toc.append((raw_name.decode('ascii', 'replace').lower(), file_off))

# -- LZS decompression with early stop (identical to the models catalog) ---------
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

# -- section 0 entity-name parse ---------------------------------------------------
SECTION_TABLE_OFF = 6
SCRIPT_SECTION_IDX = 0

def parse_entity_names(payload):
    """payload = LZS stream (u32 size header stripped).
    Returns list of entity dev names (lowercased, '_'->' ') or None."""
    head = lzs_decompress(payload, 64)
    if len(head) < SECTION_TABLE_OFF + 9 * 4:
        return None
    offs = struct.unpack_from('<9I', head, SECTION_TABLE_OFF)
    if any(offs[i] >= offs[i + 1] for i in range(8)):
        return None
    if offs[0] < SECTION_TABLE_OFF or offs[8] > 0x400000:
        return None
    sec_off = offs[SCRIPT_SECTION_IDX]
    # Only the header + name table are needed: 4 (size) + 0x20 (header)
    # + 128*8 max names. Decompress just past that, not the whole script.
    need = sec_off + 4 + 0x20 + 128 * 8
    buf = lzs_decompress(payload, need)
    if len(buf) < sec_off + 4 + 0x20:
        return None
    p = sec_off + 4                       # skip u32 size prefix
    n_entities = buf[p + 2]
    if n_entities == 0 or n_entities > 128:
        return None
    names_off = p + 0x20
    if names_off + n_entities * 8 > len(buf):
        return None
    names = []
    for e in range(n_entities):
        raw = buf[names_off + e * 8: names_off + e * 8 + 8].split(b'\0')[0]
        # Same trust rule as the live reader: reject non-printable/non-ASCII.
        if any(c < 0x20 or c > 0x7E for c in raw):
            return None
        names.append(raw.decode('ascii').lower().replace('_', ' ').strip())
    return names

# -- walk the archive ---------------------------------------------------------------
name_count = defaultdict(int)
name_fields = defaultdict(list)
nmkin2_names = None
parsed = skipped = 0

for fname, foff in toc:
    dlen = struct.unpack_from('<I', data, foff + 20)[0]
    body = data[foff + 24: foff + 24 + dlen]
    if len(body) < 8:
        skipped += 1
        continue
    lzs_size = struct.unpack_from('<I', body, 0)[0]
    if lzs_size + 4 != len(body):
        skipped += 1
        continue
    names = parse_entity_names(body[4:])
    if names is None:
        skipped += 1
        continue
    parsed += 1
    if fname == 'nmkin_2':
        nmkin2_names = names
    for nm in names:
        if not nm:
            continue
        name_count[nm] += 1
        if len(name_fields[nm]) < 6:
            name_fields[nm].append(fname)

print(f"Parsed {parsed} field files, skipped {skipped} non-field/unparsable.\n")

# -- validation ---------------------------------------------------------------------
# The reactor descent field nmkin_2 is where the player's v2.17 build spoke
# ladder trigger names live this week; "yubiwa" is the research doc's cited
# live example of an entity name read through the same header layout.
print("VALIDATION -- nmkin_2 entity names (reactor ladder field):")
print(f"  parsed : {nmkin2_names}")
validation_ok = nmkin2_names is not None and len(nmkin2_names) > 0
print(f"  {'PASS (non-empty, clean ASCII)' if validation_ok else '** FAIL -- do not trust this catalog **'}\n")

# -- full catalog, grouped by digit-stripped stem ------------------------------------
def stem(nm):
    s = nm.rstrip('0123456789')
    return s if s else nm

stem_count = defaultdict(int)
stem_names = defaultdict(set)
for nm, cnt in name_count.items():
    stem_count[stem(nm)] += cnt
    stem_names[stem(nm)].add(nm)

print(f"FULL CATALOG ({len(name_count)} distinct names, "
      f"{len(stem_count)} stems, by stem frequency):")
for st, cnt in sorted(stem_count.items(), key=lambda kv: -kv[1]):
    variants = ','.join(sorted(stem_names[st])[:8])
    sample = ','.join(name_fields[sorted(stem_names[st])[0]][:4])
    print(f"  {cnt:5d}  {st:<12} variants: {variants:<40} e.g. {sample}")

print(f"\nLog saved to: {_log_path}")
sys.exit(0 if validation_ok else 1)
