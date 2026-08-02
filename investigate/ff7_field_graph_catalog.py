#!/usr/bin/env python3
"""
ff7_field_graph_catalog.py -- Generate AccessibilityMod/src/ff7_field_graph.h:
the game-wide GATEWAY edge table for the cross-field journey graph
(2026-08-02, v2.30.65).

WHY:
  The journey feature ("guide me back to Sector 7 slums") routes over a
  graph whose nodes are fields and whose edges are the ways OUT of each
  field. Those edges come from two catalogs:
    - script-exit edges: ALREADY generated (ff7_line_trigger_catalog.h,
      kinds EXIT/EXIT_OK with a known dest field) -- reused at runtime;
    - GATEWAY edges (walk-across exit lines in the trigger section):
      generated HERE, offline from flevel.lgp.
  Only {src, dst, slot} is emitted: the mod re-reads the gateway's live
  vertices from the parsed trigger header at guidance time (same source
  the Exits category uses), so geometry is never stale and the header
  stays small. The slot is the edge's identity -- it must be the RAW
  gateway index 0..11, because that is how the mod addresses the live
  header.

ELIGIBILITY mirrors the mod's Exits category build exactly (proxy.cpp):
  dest field id != 0x7FFF and >= 0, and the exit line is not degenerate
  (both vertices all-zero = empty slot). Self-loops are dropped (a few
  fields gate to themselves for camera swaps -- useless for routing).
  World-map destinations are KEPT in the data; the mod filters them at
  runtime (journeys are field-only for now) -- keeping them here means a
  future world-nav feature reuses this header unchanged.

VALIDATION: edge count is cross-checked against the 2026-08-02 dump
  (ff7_gateway_flevel_dump.py: 1036 used gateways) minus the dropped
  self-loops; any mismatch beyond that prints loudly.

Output teed to a timestamped log (standing investigation-script rule).
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"field_graph_catalog_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    print("ERROR: flevel.lgp not found")
    sys.exit(1)
print(f"Reading: {lgp_path}")
data = open(lgp_path, 'rb').read()
n_files = struct.unpack_from('<I', data, 12)[0]
toc = []
for i in range(n_files):
    off = 16 + i * 27
    nm = data[off:off + 20].split(b'\0')[0].decode('ascii', 'replace').lower()
    toc.append((nm, struct.unpack_from('<I', data, off + 20)[0]))

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

mo = next((o for nm, o in toc if nm == 'maplist'), None)
mlen = struct.unpack_from('<I', data, mo + 20)[0]
mraw = data[mo + 24:mo + 24 + mlen]
start = next((s for s in (0, 2)
              if mraw[s + 122 * 32:s + 123 * 32].split(b'\0')[0] == b'nmkin_2'),
             None)
if start is None:
    print("ERROR: maplist anchor failed")
    sys.exit(1)
name_to_id = {}
fid = 0
for off in range(start, len(mraw) - 31, 32):
    nm = mraw[off:off + 32].split(b'\0')[0].decode('ascii', 'replace').lower()
    if nm:
        name_to_id.setdefault(nm, fid)
    fid += 1
print(f"maplist: {fid} ids\n")

UNUSED = 0x7FFF
edges = []          # (src, dst, slot)
raw_used = 0
self_loops = 0
degenerate = 0

for fname, entry_off in toc:
    if fname not in name_to_id:
        continue
    src_id = name_to_id[fname]
    flen = struct.unpack_from('<I', data, entry_off + 20)[0]
    raw = data[entry_off + 24:entry_off + 24 + flen]
    if len(raw) < 8:
        continue
    dec = lzs_decompress(raw[4:], 4 * 1024 * 1024)
    if len(dec) < 6 + 36:
        continue
    sec_offs = struct.unpack_from('<9I', dec, 6)
    if sec_offs[0] != 0x2A or any(sec_offs[i] >= sec_offs[i + 1]
                                  for i in range(8)):
        continue
    tg = sec_offs[7] + 4
    if tg + 0x2E4 > len(dec):
        continue
    hdr = dec[tg:tg + 0x2E4]
    for g in range(12):
        r = hdr[0x38 + g * 24: 0x38 + (g + 1) * 24]
        v = struct.unpack_from('<6h', r, 0)          # two exit-line vertices
        did = struct.unpack_from('<h', r, 18)[0]
        if did == UNUSED or did < 0:
            continue
        raw_used += 1
        if v[0] == 0 and v[1] == 0 and v[3] == 0 and v[4] == 0:
            degenerate += 1                          # mirrors the Exits build
            continue
        if did == src_id:
            self_loops += 1
            continue
        edges.append((src_id, did, g))

edges.sort()
print(f"raw used gateways: {raw_used} (dump cross-check expects 1036)")
print(f"dropped: {self_loops} self-loops, {degenerate} degenerate lines")
print(f"emitted edges: {len(edges)}")
if raw_used != 1036:
    print("*** WARNING: raw count differs from the 2026-08-02 dump -- "
          "game data changed? Investigate before shipping. ***")

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        '..', 'AccessibilityMod', 'src', 'ff7_field_graph.h')
out_path = os.path.normpath(out_path)
with open(out_path, 'w', encoding='ascii') as f:
    f.write(
        "// ff7_field_graph.h -- GENERATED by\n"
        "// investigate/ff7_field_graph_catalog.py "
        f"({datetime.date.today().isoformat()}); do not hand-edit.\n"
        "// Re-run the script after any game-data change.\n"
        "//\n"
        "// GATEWAY edges of the cross-field journey graph (v2.30.65): one\n"
        "// row per usable walk-across exit line, offline from flevel.lgp's\n"
        "// trigger sections. Only {src, dst, slot} is stored -- the mod\n"
        "// re-reads the gateway's live vertices from the parsed trigger\n"
        "// header (FIELD_TRIGGERS_HEADER_PTR) at guidance time, so this\n"
        "// table can never disagree with what the engine walks on. slot is\n"
        "// the RAW gateway index 0..11 (the header addressing identity).\n"
        "// Script-exit edges are NOT here -- they come from\n"
        "// ff7_line_trigger_catalog.h (kinds EXIT/EXIT_OK) at runtime.\n"
        "// Eligibility mirrors the Exits category build: real dest id +\n"
        "// non-degenerate exit line; self-loops dropped. World-map\n"
        "// destinations kept (runtime filters; future world-nav reuse).\n"
        "//\n"
        f"// stats: {len(edges)} edges from {raw_used} used gateways\n"
        f"// ({self_loops} self-loops, {degenerate} degenerate dropped)\n"
        "#pragma once\n"
        "#include <cstdint>\n\n"
        "namespace FF7FieldGraph {\n\n"
        "struct GatewayEdge {\n"
        "    uint16_t src;    // maplist field id of the field being left\n"
        "    uint16_t dst;    // maplist field id the gateway leads to\n"
        "    uint8_t  slot;   // raw gateway index 0..11 in src's header\n"
        "};\n\n"
        "// Sorted by (src, slot) for linear per-field scans.\n"
        "inline constexpr GatewayEdge kGatewayEdges[] = {\n")
    for src, dst, slot in edges:
        f.write(f"    {{{src}, {dst}, {slot}}},\n")
    f.write(
        "};\n\n"
        "inline constexpr size_t kGatewayEdgeCount =\n"
        "    sizeof(kGatewayEdges) / sizeof(kGatewayEdges[0]);\n\n"
        "} // namespace FF7FieldGraph\n")
print(f"\nWrote {out_path}")
print(f"Log saved to: {_log_path}")
