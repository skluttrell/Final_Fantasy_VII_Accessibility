#!/usr/bin/env python3
"""
ff7_maplist_catalog.py -- Extract the game's own field-id -> internal-name
table (the "maplist" file inside flevel.lgp) and generate a C++ header the
mod can bake in (2026-07-16; user request: exits should say WHERE THEY
LEAD, not "Exit 1").

WHY:
  Every gateway in the field triggers header stores its DESTINATION FIELD
  ID (+0x12, v2.14) — the number the engine jumps to. maplist is the
  engine's id->filename table (MAPJUMP and the gateways index it), so
  baking it gives every exit a real destination name ("To nmkin 2") with
  zero runtime scanning. The friendly-caption layer (v2.24 buffer,
  session-learned per visited field) rides on top of this fallback.

FORMAT (empirical, validated below): the maplist file is consecutive
  32-byte zero-padded ASCII names; index = field id. The script checks
  both "names start at +0" and "u16 count prefix at +0, names at +2"
  hypotheses and picks whichever satisfies the anchors.

VALIDATION ANCHORS (live-known id->name pairs from this project's logs):
  field 122 = "nmkin_2"  (2026-07-16 session: WALL gates field=122 while
                          the reactor's ladder lines were listed)
  field 116 / 117        (the v2.24 verify walked these: their names must
                          look like the Sector-1-station area's fields)

Output: full id->name listing + generated header
  AccessibilityMod/src/ff7_field_names.h
"""
import sys, os, struct, datetime

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"maplist_catalog_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
print(f"Reading: {lgp_path}")
data = open(lgp_path, 'rb').read()

n_files = struct.unpack_from('<I', data, 12)[0]
maplist_off = None
for i in range(n_files):
    off = 16 + i * 27
    raw_name = data[off:off + 20].split(b'\0')[0]
    if raw_name.lower() == b'maplist':
        maplist_off = struct.unpack_from('<I', data, off + 20)[0]
        break
if maplist_off is None:
    print("ERROR: maplist not found in flevel TOC.")
    sys.exit(1)

flen = struct.unpack_from('<I', data, maplist_off + 20)[0]
raw = data[maplist_off + 24:maplist_off + 24 + flen]
print(f"maplist: {flen} bytes at archive offset 0x{maplist_off:X}")
print("first 64 bytes: " + ' '.join(f"{b:02X}" for b in raw[:64]) + "\n")

def parse(names_start):
    names = []
    for off in range(names_start, len(raw) - 31, 32):
        name = raw[off:off + 32].split(b'\0')[0].decode('ascii', 'replace')
        names.append(name)
    return names

# Hypothesis A: names from +0. Hypothesis B: u16 count at +0, names at +2.
for start, label in ((0, "names at +0"), (2, "u16 count + names at +2")):
    names = parse(start)
    ok122 = len(names) > 122 and names[122] == 'nmkin_2'
    print(f"Hypothesis '{label}': {len(names)} entries; "
          f"[122]='{names[122] if len(names)>122 else '??'}' "
          f"{'ANCHOR OK' if ok122 else 'anchor failed'}")
    if ok122:
        break
else:
    print("NEITHER hypothesis satisfies the nmkin_2 anchor -- aborting, "
          "format needs a closer look.")
    sys.exit(1)

print(f"\nAnchor context: [116]='{names[116]}' [117]='{names[117]}' "
      f"[118]='{names[118]}' [121]='{names[121]}' [122]='{names[122]}'")

blanks = sum(1 for n in names if not n)
print(f"\nTotal entries: {len(names)}  (blank: {blanks})")
for i, n in enumerate(names):
    print(f"  {i:4d}: {n}")

# -- generate the C++ header --------------------------------------------------------
hdr_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        '..', 'AccessibilityMod', 'src', 'ff7_field_names.h')
hdr_path = os.path.abspath(hdr_path)
with open(hdr_path, 'w', encoding='utf-8') as f:
    f.write(f"""/*
 * ff7_field_names.h -- GENERATED FILE, do not edit by hand.
 *
 * The game's own field-id -> internal-name table, extracted from the
 * "maplist" file inside flevel.lgp by investigate/ff7_maplist_catalog.py
 * ({datetime.date.today().isoformat()}). Index = field id, the same id
 * space the triggers-header gateways store at +0x12 (v2.14) and MAPJUMP
 * uses. Validated against the live anchor field 122 == "nmkin_2"
 * (2026-07-16 session logs).
 *
 * Used by the v2.25 exit naming ("To nmkin 2") as the always-available
 * fallback beneath the friendly-caption layer (visited-place cache fed
 * by the v2.24 MPNAM buffer).
 */

#pragma once

namespace FF7FieldNames {{

constexpr int kCount = {len(names)};

// Plain ASCII (maplist is ASCII); empty string = unused id.
inline const char* const kNames[kCount] = {{
""")
    for i, n in enumerate(names):
        esc = n.replace('\\', '\\\\').replace('"', '\\"')
        f.write(f'    "{esc}",{" " * max(1, 12 - len(esc))}// {i}\n')
    f.write("""};

// Name for a field id, or nullptr when out of range / blank.
inline const char* Get(int field_id)
{
    if (field_id < 0 || field_id >= kCount || kNames[field_id][0] == '\\0')
        return nullptr;
    return kNames[field_id];
}

} // namespace FF7FieldNames
""")
print(f"\nGenerated: {hdr_path}")
print("Done.")
