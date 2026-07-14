#!/usr/bin/env python3
"""
ff7_flevel_models_catalog.py -- Game-wide catalog of field model dev-name
labels, extracted OFFLINE from flevel.lgp (2026-07-14).

WHY:
  Next pathfinder category: Items (treasure chests / floor pickups /
  containers). Those are ordinary field models with scripts, so the v2.16
  label machinery can classify them -- IF we know what the developers named
  them. Rather than guessing keywords from the handful of fields the player
  has visited (the way the "save" save-point heuristic had to be shipped),
  this script reads EVERY field in the game from flevel.lgp and prints every
  model label with its frequency, HRC file, and sample fields. The chest /
  potion / materia naming patterns can then be read off the complete
  dataset, and the "save" heuristic gets checked game-wide for free.

HOW:
  flevel.lgp is an LGP archive (qhimm-documented): 12-byte magic header,
  u32 file count, 27-byte TOC entries (char name[20], u32 offset, u8 check,
  u16 conflict). Each file at offset: char name[20] repeated, u32 length,
  data. Field files inside are LZS-compressed (u32 compressed-size header,
  then LZSS: 4KB ring buffer initialized to zero, write pointer starts at
  0xFEE, control byte LSB-first, 1=literal, 0=two-byte back-reference:
  pos = b1 | ((b2 & 0xF0) << 4), len = (b2 & 0x0F) + 3).

  Decompressed field = the exact in-memory layout the mod already parses
  live: nine u32 section offsets at +6, model loader = section index 2,
  entries per the v2.16-decoded format (u16-len-prefixed .char name, u16,
  char[8] HRC, char[4] scale, u16 nAnims, 30B light, anims). Decompression
  stops early at the end of section 2 -- the model section sits near the
  front of the file, so each field costs only a few KB of LZSS work.

  Non-field files in the archive (maplist, *.tut, ...) fail the section-
  table sanity checks and are skipped and counted.

VALIDATION: md1stin's 10 labels are known from the live dump
  (ff7_field_models_verify.py, v2.16) -- the catalog must reproduce them.

Output: full label catalog (count, HRCs, sample fields) + keyword scans for
item/save candidates. Feeds the Items-category classification.
"""
import sys, os, struct, datetime
from collections import defaultdict

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"flevel_models_catalog_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
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

# -- LGP table of contents -------------------------------------------------------
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

# -- LZS decompression with early stop -------------------------------------------
def lzs_decompress(src, max_out):
    """FF7 LZSS. src = raw stream (after the u32 size header). Stops once
    max_out bytes are produced. Returns bytes (may be shorter if the stream
    ends first)."""
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

# -- field model-section parse (v2.16 format, mirrors FieldModelLabel) -----------
SECTION_TABLE_OFF = 6
MODEL_SECTION_IDX = 2

def parse_field_models(payload, field_name):
    """payload = LZS stream (u32 size header already stripped).
    Returns list of (label, hrc) or None if not a parsable field file."""
    head = lzs_decompress(payload, 64)
    if len(head) < SECTION_TABLE_OFF + 9 * 4:
        return None
    offs = struct.unpack_from('<9I', head, SECTION_TABLE_OFF)
    # Sanity: strictly ascending, plausible range (the same checks the live
    # parser applies before trusting a section offset).
    if any(offs[i] >= offs[i + 1] for i in range(8)):
        return None
    if offs[0] < SECTION_TABLE_OFF or offs[8] > 0x400000:
        return None
    sec_off = offs[MODEL_SECTION_IDX]
    end_off = offs[MODEL_SECTION_IDX + 1]
    buf = lzs_decompress(payload, end_off)
    if len(buf) < end_off:
        return None
    sec_size = struct.unpack_from('<I', buf, sec_off)[0]
    if sec_size < 8 or sec_size > 0x10000:
        return None
    p = sec_off + 4
    end = p + sec_size
    if end > len(buf):
        return None
    n_models = struct.unpack_from('<H', buf, p + 2)[0]
    if n_models > 64:
        return None
    p += 6
    models = []
    for _ in range(n_models):
        if p + 2 > end: return None
        nlen = struct.unpack_from('<H', buf, p)[0]; p += 2
        if nlen == 0 or nlen > 64 or p + nlen > end: return None
        raw = buf[p:p + nlen]; p += nlen
        name = raw.decode('ascii', 'replace').lower()
        if name.endswith('.char'):
            name = name[:-5]
        if name.startswith(field_name):
            name = name[len(field_name):]
        label = name.replace('_', ' ').strip()
        p += 2                       # unknown u16
        if p + 8 > end: return None
        hrc = buf[p:p + 8].split(b'\0')[0].decode('ascii', 'replace').upper()
        p += 8
        p += 4                       # ASCII scale
        if p + 2 > end: return None
        nanim = struct.unpack_from('<H', buf, p)[0]; p += 2
        if nanim > 64: return None
        p += 30                      # light block
        for _ in range(nanim):
            if p + 2 > end: return None
            alen = struct.unpack_from('<H', buf, p)[0]; p += 2
            if alen > 64 or p + alen + 2 > end: return None
            p += alen + 2
        models.append((label, hrc))
    return models

# -- walk the archive -------------------------------------------------------------
label_count = defaultdict(int)          # label -> total occurrences
label_hrcs = defaultdict(set)           # label -> HRC files seen
label_fields = defaultdict(list)        # label -> sample fields
parsed = skipped = 0

for fname, foff in toc:
    # File record: name[20] again, u32 length, then data (u32 LZS size + stream).
    dlen = struct.unpack_from('<I', data, foff + 20)[0]
    body = data[foff + 24: foff + 24 + dlen]
    if len(body) < 8:
        skipped += 1
        continue
    lzs_size = struct.unpack_from('<I', body, 0)[0]
    if lzs_size + 4 != len(body):
        skipped += 1                    # not LZS-wrapped -> not a field file
        continue
    models = parse_field_models(body[4:], fname)
    if models is None:
        skipped += 1
        continue
    parsed += 1
    for label, hrc in models:
        label_count[label] += 1
        label_hrcs[label].add(hrc)
        if len(label_fields[label]) < 6:
            label_fields[label].append(fname)

print(f"Parsed {parsed} field files, skipped {skipped} non-field/unparsable.\n")

# -- validation: md1stin ----------------------------------------------------------
print("VALIDATION -- md1stin labels (expect the 10 from the v2.16 live dump):")
md1 = [(lbl, h) for lbl in label_fields for h in ()  # placeholder
       ]
found_md1 = [lbl for lbl, flds in label_fields.items() if 'md1stin' in flds]
for lbl in sorted(found_md1):
    print(f"  {lbl!r}")
print()

# -- full catalog -------------------------------------------------------------------
print(f"FULL CATALOG ({len(label_count)} distinct labels, by frequency):")
for lbl, cnt in sorted(label_count.items(), key=lambda kv: -kv[1]):
    hrcs = ','.join(sorted(label_hrcs[lbl]))
    flds = ','.join(label_fields[lbl][:4])
    print(f"  {cnt:4d}  {lbl:<28} HRC={hrcs:<24} e.g. {flds}")

# -- keyword scans ------------------------------------------------------------------
KEYWORDS = ["save", "sebu",                      # save points
            "box", "takara", "tkr", "treasure",  # chests
            "potion", "posyon", "poshon", "item",
            "materia", "mat ", "bin", "bottle", "kusuri"]
print("\nKEYWORD SCAN (item/save candidates):")
for kw in KEYWORDS:
    hits = [lbl for lbl in label_count if kw in lbl]
    if hits:
        print(f"  '{kw}': " + '; '.join(
            f"{h!r}×{label_count[h]} (HRC {','.join(sorted(label_hrcs[h]))})"
            for h in sorted(hits)))
    else:
        print(f"  '{kw}': no matches")

print(f"\nLog saved to: {_log_path}")
_log_file.close()
